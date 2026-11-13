"""Tests for SecurityVulnerabilityDetector."""

import pytest

from services.iac_scanner import IaCScanner
from services.security_detector import (
    SecurityAnalysisResult,
    SecurityVulnerabilityDetector,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)


@pytest.fixture
def detector():
    return SecurityVulnerabilityDetector()


class TestSecurityDetector:
    async def test_detect_python_sql_injection(self, detector, tmp_path):
        """Detect SQL injection via f-string in cursor.execute and verify vulnerability details."""
        code_file = tmp_path / "vuln.py"
        code_file.write_text('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")')
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert isinstance(result, SecurityAnalysisResult)
        assert result.total_files_analyzed == 1
        assert result.total_vulnerabilities_found >= 1

        # Verify the vulnerability is actually classified as SQL injection
        assert VulnerabilityType.SQL_INJECTION in result.vulnerabilities_by_type
        sql_vulns = result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION]
        assert len(sql_vulns) >= 1

        vuln = sql_vulns[0]
        assert vuln.file_path == str(code_file)
        assert vuln.language == "python"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.line_start >= 1
        assert "CWE-89" in vuln.cwe_ids
        assert vuln.remediation_advice != ""

    async def test_detect_hardcoded_password(self, detector, tmp_path):
        """Detect hardcoded password and verify it is classified as hardcoded credentials."""
        code_file = tmp_path / "config.py"
        code_file.write_text('password = "SuperSecretPassword123!"')
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert result.total_files_analyzed == 1
        assert result.total_vulnerabilities_found >= 1

        assert VulnerabilityType.HARDCODED_CREDENTIALS in result.vulnerabilities_by_type
        cred_vulns = result.vulnerabilities_by_type[VulnerabilityType.HARDCODED_CREDENTIALS]
        assert len(cred_vulns) >= 1

        vuln = cred_vulns[0]
        assert vuln.file_path == str(code_file)
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert "CWE-798" in vuln.cwe_ids
        assert "password" in vuln.code_snippet.lower()

    async def test_safe_python_code(self, detector, tmp_path):
        """No false positives on safe arithmetic code."""
        code_file = tmp_path / "safe.py"
        code_file.write_text("x = 1 + 2\nprint(x)\n")
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert result.total_files_analyzed == 1
        assert result.total_vulnerabilities_found == 0
        assert result.vulnerabilities_by_type == {}
        assert result.overall_risk_score == 0.0

    async def test_empty_file_list(self, detector):
        """Empty file list produces zero results with zero analysis time."""
        result = await detector.analyze_security_vulnerabilities([])

        assert result.total_files_analyzed == 0
        assert result.total_vulnerabilities_found == 0
        assert result.analysis_time_seconds == 0.0
        assert result.vulnerabilities_by_type == {}
        assert result.vulnerabilities_by_severity == {}
        assert result.overall_risk_score == 0.0
        # Zero files examined is ALWAYS degraded — a zero-coverage scan must never
        # be reported as clean, whether files were requested and all failed or
        # none were passed at all. (Was the exact fake-green: 0 files → grade A.)
        assert result.scan_degraded is True

    async def test_nonexistent_file(self, detector):
        """Non-existent file is skipped gracefully with zero files analyzed."""
        result = await detector.analyze_security_vulnerabilities(["/nonexistent/file.py"])

        assert result.total_files_analyzed == 0
        assert result.total_vulnerabilities_found == 0
        # Files were requested but none could be examined → degraded, so a
        # zero-finding result is not read as clean by the oracle gate.
        assert result.scan_degraded is True
        assert result.files_failed_to_parse == 1

    async def test_detect_weak_crypto(self, detector, tmp_path):
        """Detect weak crypto (md5) and verify classification and confidence filtering."""
        code_file = tmp_path / "crypto.py"
        code_file.write_text("import hashlib\nhash_val = hashlib.md5(user_input)")

        # Without low_confidence, md5 might be filtered depending on confidence score
        result_strict = await detector.analyze_security_vulnerabilities([str(code_file)])

        # With low_confidence included, md5 must be found
        result_all = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        assert result_all.total_files_analyzed == 1
        assert result_all.total_vulnerabilities_found >= 1

        assert VulnerabilityType.WEAK_CRYPTOGRAPHY in result_all.vulnerabilities_by_type
        crypto_vulns = result_all.vulnerabilities_by_type[VulnerabilityType.WEAK_CRYPTOGRAPHY]
        assert len(crypto_vulns) >= 1

        vuln = crypto_vulns[0]
        assert vuln.language == "python"
        assert "CWE-327" in vuln.cwe_ids
        assert "md5" in vuln.code_snippet.lower()

        # Verify that include_low_confidence=True actually includes more or equal results
        assert result_all.total_vulnerabilities_found >= result_strict.total_vulnerabilities_found

    async def test_detect_command_injection(self, detector, tmp_path):
        """Detect os.system command injection and verify severity is CRITICAL."""
        code_file = tmp_path / "cmd.py"
        code_file.write_text('import os\nos.system("rm -rf " + user_input)')
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert result.total_files_analyzed == 1
        assert result.total_vulnerabilities_found >= 1

        assert VulnerabilityType.COMMAND_INJECTION in result.vulnerabilities_by_type
        cmd_vulns = result.vulnerabilities_by_type[VulnerabilityType.COMMAND_INJECTION]
        assert len(cmd_vulns) >= 1

        vuln = cmd_vulns[0]
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert "CWE-78" in vuln.cwe_ids
        assert vuln.line_start >= 1
        assert vuln.line_end >= vuln.line_start

    async def test_safe_parameterized_query_not_flagged(self, detector, tmp_path):
        """The safe psycopg parameterized form (%s placeholder + params tuple) is NOT a SQLi.

        Regression pin for the inverted heuristic that flagged
        cur.execute("... %s ...", (params,)) as HIGH — the false positive that
        made an honest security_patch delta impossible.
        """
        code_file = tmp_path / "safe_db.py"
        code_file.write_text('cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n')

        result = await detector.analyze_security_vulnerabilities([str(code_file)])
        assert VulnerabilityType.SQL_INJECTION not in result.vulnerabilities_by_type

        # Strongest form: not flagged even with low-confidence findings included.
        result_all = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        assert VulnerabilityType.SQL_INJECTION not in result_all.vulnerabilities_by_type

    async def test_detect_sql_injection_concat_non_cursor_receiver(self, detector, tmp_path):
        """String concatenation into .execute() on a non-'cursor' receiver is flagged HIGH.

        The old pattern required the literal receiver `cursor.` and missed
        cur./db./conn.execute("..." + var) — exactly the live-fire miss.
        """
        code_file = tmp_path / "concat.py"
        code_file.write_text('cur.execute("SELECT * FROM users WHERE id = " + user_id)\n')

        result = await detector.analyze_security_vulnerabilities([str(code_file)])
        assert VulnerabilityType.SQL_INJECTION in result.vulnerabilities_by_type
        vuln = result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION][0]
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert "CWE-89" in vuln.cwe_ids

    async def test_detect_sql_injection_percent_format(self, detector, tmp_path):
        """Old-style %-format operator applied to a query string is flagged HIGH."""
        code_file = tmp_path / "pctfmt.py"
        code_file.write_text('cur.execute("SELECT * FROM users WHERE id = %s" % user_id)\n')

        result = await detector.analyze_security_vulnerabilities([str(code_file)])
        assert VulnerabilityType.SQL_INJECTION in result.vulnerabilities_by_type
        assert (
            result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION][0].severity
            == VulnerabilitySeverity.HIGH
        )

    async def test_detect_sql_injection_str_format(self, detector, tmp_path):
        """A str.format()-built query is flagged HIGH."""
        code_file = tmp_path / "strfmt.py"
        code_file.write_text('cur.execute("SELECT * FROM users WHERE id = {}".format(user_id))\n')

        result = await detector.analyze_security_vulnerabilities([str(code_file)])
        assert VulnerabilityType.SQL_INJECTION in result.vulnerabilities_by_type
        assert (
            result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION][0].severity
            == VulnerabilitySeverity.HIGH
        )

    async def test_detect_command_injection_shell_true_variable(self, detector, tmp_path):
        """subprocess.run with a non-literal command under shell=True is command injection."""
        code_file = tmp_path / "shell.py"
        code_file.write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")

        result = await detector.analyze_security_vulnerabilities([str(code_file)])
        assert VulnerabilityType.COMMAND_INJECTION in result.vulnerabilities_by_type
        assert "CWE-78" in (
            result.vulnerabilities_by_type[VulnerabilityType.COMMAND_INJECTION][0].cwe_ids
        )

    def test_patterns_loaded(self, detector):
        """Detector has loaded diverse security patterns covering multiple languages and types."""
        assert len(detector.patterns) > 5

        # Verify patterns cover multiple vulnerability types
        vuln_types = {p.vulnerability_type for p in detector.patterns}
        assert VulnerabilityType.SQL_INJECTION in vuln_types
        assert VulnerabilityType.COMMAND_INJECTION in vuln_types
        assert VulnerabilityType.HARDCODED_CREDENTIALS in vuln_types

        # Verify patterns cover multiple languages
        languages = {p.language for p in detector.patterns}
        assert "python" in languages
        assert "java" in languages

        # Each pattern must have at least one code_pattern regex
        for pattern in detector.patterns:
            assert len(pattern.code_patterns) > 0, f"Pattern {pattern.id} has no code_patterns"

    def test_severity_scores_defined(self, detector):
        """All severity levels have scores, and scores are ordered correctly."""
        for severity in VulnerabilitySeverity:
            assert severity in detector.severity_scores

        # Verify severity ordering: CRITICAL > HIGH > MEDIUM > LOW > INFO
        assert (
            detector.severity_scores[VulnerabilitySeverity.CRITICAL]
            > detector.severity_scores[VulnerabilitySeverity.HIGH]
        )
        assert (
            detector.severity_scores[VulnerabilitySeverity.HIGH]
            > detector.severity_scores[VulnerabilitySeverity.MEDIUM]
        )
        assert (
            detector.severity_scores[VulnerabilitySeverity.MEDIUM]
            > detector.severity_scores[VulnerabilitySeverity.LOW]
        )
        assert (
            detector.severity_scores[VulnerabilitySeverity.LOW]
            > detector.severity_scores[VulnerabilitySeverity.INFO]
        )

    async def test_multiple_vulnerabilities_in_one_file(self, detector, tmp_path):
        """A file with multiple vulnerability types reports all of them when including low confidence."""
        code_file = tmp_path / "multi_vuln.py"
        code_file.write_text(
            'password = "SuperSecret123!"\n'
            'cursor.execute(f"SELECT * FROM users WHERE id={user_input}")\n'
        )
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )

        assert result.total_files_analyzed == 1
        assert result.total_vulnerabilities_found >= 2

        found_types = set(result.vulnerabilities_by_type.keys())
        assert VulnerabilityType.HARDCODED_CREDENTIALS in found_types
        assert VulnerabilityType.SQL_INJECTION in found_types

    async def test_risk_score_increases_with_severity(self, detector, tmp_path):
        """Overall risk score is higher for critical vulnerabilities than safe code."""
        safe_file = tmp_path / "safe.py"
        safe_file.write_text("x = 1\n")
        safe_result = await detector.analyze_security_vulnerabilities([str(safe_file)])

        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('import os\nos.system("rm -rf " + user_input)')
        vuln_result = await detector.analyze_security_vulnerabilities([str(vuln_file)])

        assert vuln_result.overall_risk_score > safe_result.overall_risk_score

    async def test_max_files_parameter_limits_analysis(self, detector, tmp_path):
        """The max_files parameter limits how many files are analyzed."""
        for i in range(5):
            f = tmp_path / f"file_{i}.py"
            f.write_text(f'password = "secret{i}password!"')

        file_paths = [str(tmp_path / f"file_{i}.py") for i in range(5)]
        result = await detector.analyze_security_vulnerabilities(file_paths, max_files=2)

        assert result.total_files_analyzed == 2

    async def test_vulnerability_has_remediation_and_references(self, detector, tmp_path):
        """Detected vulnerabilities include actionable remediation advice and CVE references."""
        code_file = tmp_path / "vuln.py"
        code_file.write_text('cursor.execute(f"SELECT * FROM users WHERE id={uid}")')
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert result.total_vulnerabilities_found >= 1
        sql_vulns = result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION]
        vuln = sql_vulns[0]

        # Must have non-empty remediation advice
        assert len(vuln.remediation_advice) > 10
        assert "parameterized" in vuln.remediation_advice.lower()

        # Must have CVE references
        assert len(vuln.references) > 0
        assert any(ref.startswith("CVE-") for ref in vuln.references)

    async def test_real_engines_merge_no_double_count(self, detector, tmp_path):
        """A finding both the regex engine and bandit flag is reported ONCE.

        f-string SQLi is caught by the regex rule (HIGH) AND bandit B608 (MEDIUM)
        on the same line; the merge de-dupes to a single SQL_INJECTION finding,
        and the higher-severity regex match (with rich remediation) wins.
        """
        code_file = tmp_path / "vuln.py"
        code_file.write_text('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")\n')
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        sql_vulns = result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION]
        # Exactly one — not two (no per-engine double count on the same line).
        assert len(sql_vulns) == 1
        assert sql_vulns[0].severity == VulnerabilitySeverity.HIGH

    def test_merge_dedups_bandit_and_semgrep_same_finding(self, detector):
        """A SQLi flagged by BOTH bandit and semgrep at the same line is reported
        ONCE (no double-count), and the higher-severity match wins."""

        def _m(engine, severity, line, code):
            return VulnerabilityMatch(
                id=f"{engine}_{line}",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=severity,
                confidence=VulnerabilityConfidence.HIGH,
                file_path="/app/x.py",
                language="python",
                line_start=line,
                line_end=line,
                code_snippet=code,
                # Every real producer stamps this (R216); the merge now keys
                # cross-engine duplicates off it instead of inferring a producer
                # from the id shape.
                engine=engine,
            )

        bandit = _m("bandit", VulnerabilitySeverity.MEDIUM, 5, "cur.execute('...' % x)")
        semgrep = _m("semgrep", VulnerabilitySeverity.HIGH, 5, "cur.execute('...' % x)")
        # plus a distinct finding on another line that must survive separately
        semgrep_other = _m("semgrep", VulnerabilitySeverity.HIGH, 9, "cur.execute('...' + y)")

        merged = detector._merge_matches([bandit], [semgrep, semgrep_other], True)
        sqli = [m for m in merged if m.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        same_line = [m for m in sqli if m.line_start == 5]
        assert len(same_line) == 1  # bandit+semgrep collapsed to one
        assert same_line[0].severity == VulnerabilitySeverity.HIGH  # higher wins
        assert any(m.line_start == 9 for m in sqli)  # distinct line kept

    def test_merge_iac_finding_is_distinct_from_source(self, detector):
        """An IaC misconfig (Dockerfile) and a source SAST finding (.py) live in
        different files -> both survive the merge and are counted (no collision,
        no double-count)."""
        bandit_py = VulnerabilityMatch(
            id="bandit_3",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            confidence=VulnerabilityConfidence.HIGH,
            file_path="/app/db.py",
            language="python",
            line_start=3,
            line_end=3,
            code_snippet="cur.execute('...' + x)",
        )
        iac_docker = VulnerabilityMatch(
            id="trivy_config_AVD-DS-0002_Dockerfile_1",
            vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
            severity=VulnerabilitySeverity.HIGH,
            confidence=VulnerabilityConfidence.HIGH,
            file_path="Dockerfile",
            language="dockerfile",
            line_start=1,
            line_end=1,
            pattern_id="AVD-DS-0002",
            code_snippet="FROM ubuntu:latest",
        )
        merged = detector._merge_matches([], [bandit_py, iac_docker], True)
        assert len(merged) == 2
        high = [m for m in merged if m.severity == VulnerabilitySeverity.HIGH]
        assert len(high) == 2  # both contribute to the high count the gate sums
        assert {m.file_path for m in merged} == {"/app/db.py", "Dockerfile"}

    def test_merge_keeps_distinct_compose_findings_on_one_line(self, detector, tmp_path):
        """Round-2: compose findings sharing one line must survive the REPORT
        merge. Two flow-style services plus two different checks on one line
        previously collapsed 3 -> 1 by (file, line, type)."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services: {a: {privileged: true, network_mode: host}, b: {privileged: true}}\n"
        )
        findings = IaCScanner()._scan_compose(str(compose))
        assert len(findings) == 3
        assert {m.line_start for m in findings} == {1}

        merged = detector._merge_matches([], findings, True)
        assert len(merged) == 3
        assert sorted(m.pattern_id for m in merged) == [
            "COMPOSE-NETWORK-HOST",
            "COMPOSE-PRIVILEGED",
            "COMPOSE-PRIVILEGED",
        ]

    async def test_regex_fallback_when_engines_absent(self, detector, tmp_path):
        """With the real engines unavailable, the regex engine still gates honestly."""
        detector._bandit.bandit_available = False
        detector._secrets.secrets_available = False
        detector._semgrep.semgrep_available = False

        code_file = tmp_path / "vuln.py"
        code_file.write_text('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")\n')
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert VulnerabilityType.SQL_INJECTION in result.vulnerabilities_by_type
        assert (
            result.vulnerabilities_by_type[VulnerabilityType.SQL_INJECTION][0].severity
            == VulnerabilitySeverity.HIGH
        )

    async def test_real_secret_engine_detects_credential(self, detector, tmp_path):
        """detect-secrets surfaces a hardcoded secret through the detector pipeline."""
        code_file = tmp_path / "settings.py"
        code_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')  # pragma: allowlist secret
        result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert VulnerabilityType.HARDCODED_CREDENTIALS in result.vulnerabilities_by_type
