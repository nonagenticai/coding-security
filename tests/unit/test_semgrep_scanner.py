"""Tests for the real semgrep multi-language SAST scanner.

semgrep is installed as an ISOLATED CLI in the Docker image (it pins rich<13.6,
irreconcilable with the app venv), so it is NOT present in the CI uv venv. These
tests therefore drive the parse/map/scan logic via canned semgrep JSON +
monkeypatched subprocess (CLI-agnostic), and gate the single live-CLI test on
availability so it runs locally / in-pod but skips in CI.
"""

import json
from pathlib import Path

import pytest

from services.scanner_errors import ScannerExecutionError
from services.security_detector import (
    VulnerabilityConfidence,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from services.semgrep_scanner import SemgrepScanner

FIXTURE_RULES = Path(__file__).parent.parent / "fixtures" / "semgrep-rules.yml"


def _result(
    *,
    check_id="python.lang.security.audit.formatted-sql-query.formatted-sql-query",
    path="/app/vuln.py",
    line=2,
    severity="ERROR",
    lines='cur.execute("SELECT * FROM t WHERE id = " + uid)',
    cwe=("CWE-89: Improper Neutralization of Special Elements used in an SQL Command",),
    owasp=("A03:2021 - Injection",),
    confidence="HIGH",
):
    metadata = {}
    if cwe is not None:
        metadata["cwe"] = list(cwe)
    if owasp is not None:
        metadata["owasp"] = list(owasp)
    if confidence is not None:
        metadata["confidence"] = confidence
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 5},
        "end": {"line": line, "col": 50},
        "extra": {
            "message": "Possible SQL injection.",
            "severity": severity,
            "lines": lines,
            "metadata": metadata,
        },
    }


def _payload(results, errors=None):
    return json.dumps({"results": results, "errors": errors or []})


@pytest.fixture
def scanner():
    return SemgrepScanner()


class TestSemgrepParseMap:
    def test_sql_injection_python(self, scanner):
        matches = scanner._parse_semgrep_json(_payload([_result()]))
        assert len(matches) == 1
        m = matches[0]
        assert m.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert m.severity == VulnerabilitySeverity.HIGH  # semgrep ERROR -> HIGH
        assert m.confidence == VulnerabilityConfidence.HIGH
        assert m.language == "python"
        assert m.pattern_id.endswith("formatted-sql-query")
        assert m.code_snippet  # extra.lines mapped through
        assert any("CWE-89" in c for c in m.cwe_ids)
        assert m.owasp_categories == ["A03:2021 - Injection"]
        assert m.line_start == 2

    def test_javascript_path_language(self, scanner):
        matches = scanner._parse_semgrep_json(
            _payload([_result(path="/app/web/query.js", check_id="javascript.sql.injection")])
        )
        assert matches[0].language == "javascript"
        assert matches[0].vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_weak_crypto_warning_severity_and_default_confidence(self, scanner):
        matches = scanner._parse_semgrep_json(
            _payload(
                [
                    _result(
                        severity="WARNING",
                        cwe=("CWE-327: Use of a Broken or Risky Cryptographic Algorithm",),
                        confidence=None,  # no confidence -> default MEDIUM
                    )
                ]
            )
        )
        m = matches[0]
        assert m.vulnerability_type == VulnerabilityType.WEAK_CRYPTOGRAPHY
        assert m.severity == VulnerabilitySeverity.MEDIUM  # WARNING -> MEDIUM
        assert m.confidence == VulnerabilityConfidence.MEDIUM

    def test_no_cwe_falls_back_to_information_disclosure(self, scanner):
        matches = scanner._parse_semgrep_json(_payload([_result(cwe=None)]))
        assert matches[0].vulnerability_type == VulnerabilityType.INFORMATION_DISCLOSURE

    def test_cwe_as_plain_string(self, scanner):
        # semgrep sometimes emits metadata.cwe as a bare string, not a list.
        raw = json.loads(_payload([_result(cwe=None)]))
        raw["results"][0]["extra"]["metadata"]["cwe"] = "CWE-89: SQL Injection"
        matches = scanner._parse_semgrep_json(json.dumps(raw))
        assert matches[0].vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert matches[0].cwe_ids == ["CWE-89"]

    def test_errors_present_results_still_returned(self, scanner):
        """The parser keeps findings when errors[] is present; scan() reports that run as degraded (R216)."""
        matches = scanner._parse_semgrep_json(
            _payload([_result()], errors=[{"message": "could not parse other.py"}])
        )
        assert len(matches) == 1

    def test_parse_empty_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_semgrep_json("")

    def test_parse_malformed_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_semgrep_json("{not json")

    def test_parse_non_dict_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_semgrep_json("[1, 2, 3]")

    def test_no_rules_loaded_empty_results(self, scanner):
        # Registry unreachable -> semgrep returns empty results -> no matches.
        assert scanner._parse_semgrep_json(_payload([])) == []


class TestSemgrepScanOrchestration:
    async def test_unavailable_returns_empty(self):
        scanner = SemgrepScanner()
        scanner.semgrep_available = False
        assert await scanner.scan(["/app/vuln.py"]) == []
        assert scanner.is_available() is False

    async def test_no_targets_returns_empty(self):
        scanner = SemgrepScanner()
        scanner.semgrep_available = True
        assert await scanner.scan([]) == []

    async def test_scan_invokes_cli_and_parses(self, monkeypatch):
        """scan() builds the command, runs it, and maps the JSON (CLI mocked)."""
        scanner = SemgrepScanner()
        scanner.semgrep_available = True
        scanner.ruleset = "auto"

        captured = {}

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_result()]).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            captured["cmd"] = cmd
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        matches = await scanner.scan(["/app/vuln.py"])
        assert len(matches) == 1
        assert matches[0].vulnerability_type == VulnerabilityType.SQL_INJECTION
        # command carries the configured ruleset, json + the target
        assert "--config" in captured["cmd"]
        assert "auto" in captured["cmd"]
        assert "--json" in captured["cmd"]
        assert "/app/vuln.py" in captured["cmd"]

    async def test_only_dotenv_targets_are_withheld_from_semgrep(self, monkeypatch, tmp_path):
        """semgrep keeps Dockerfile/HCL/JSON/YAML coverage; only dotenv is withheld.

        The vendored pack has Dockerfile, Terraform/HCL, JSON and YAML rules, so
        those targets were analysed before .env support was added and must keep
        reaching the CLI. Dotenv files have no language and appear in
        ``errors[]``, which degrades the whole engine, so only they are dropped.
        """
        scanner = SemgrepScanner()
        scanner.semgrep_available = True

        captured = {}

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([]).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            captured["cmd"] = cmd
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        py = tmp_path / "app.py"
        js = tmp_path / "app.js"
        yml = tmp_path / "ci.yml"
        dockerfile = tmp_path / "Dockerfile"
        terraform = tmp_path / "main.tf"
        cfn = tmp_path / "stack.json"
        env = tmp_path / ".env"
        env_local = tmp_path / ".env.local"
        for f in (py, js, yml, dockerfile, terraform, cfn, env, env_local):
            f.write_text("x\n")

        await scanner.scan([py, js, yml, dockerfile, terraform, cfn, env, env_local])

        for kept in (py, js, yml, dockerfile, terraform, cfn):
            assert str(kept) in captured["cmd"]
        for withheld in (env, env_local):
            assert str(withheld) not in captured["cmd"]

    async def test_no_targets_besides_dotenv_skips_the_cli(self, monkeypatch, tmp_path):
        """A dotenv-only target set runs no semgrep process at all."""
        scanner = SemgrepScanner()
        scanner.semgrep_available = True

        async def _boom(*args, **kwargs):
            raise AssertionError("semgrep must not run without a non-dotenv target")

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _boom)
        env = tmp_path / ".env"
        env_local = tmp_path / ".env.local"
        env.write_text("A=1\n")
        env_local.write_text("B=2\n")
        assert await scanner.scan([env, env_local]) == []

    def test_is_available_uses_which_not_subprocess(self, monkeypatch):
        """Availability is probed via shutil.which (instant) — NEVER by shelling
        `semgrep --version`, whose slow cold start would false-negative in-cluster
        and leave the engine inert in the request path."""
        import services.semgrep_scanner as mod

        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/local/bin/semgrep")

        def _boom(*a, **k):
            raise AssertionError("subprocess must not run for availability")

        monkeypatch.setattr(mod.subprocess, "run", _boom)
        s = SemgrepScanner()
        assert s.is_available() is True
        assert s.semgrep_version is None  # version is lazy, not resolved in __init__

    def test_is_unavailable_when_which_returns_none(self, monkeypatch):
        import services.semgrep_scanner as mod

        monkeypatch.setattr(mod.shutil, "which", lambda name: None)
        assert SemgrepScanner().is_available() is False

    def test_ruleset_env_override(self, monkeypatch):
        monkeypatch.setenv("SEMGREP_RULESET", "/etc/semgrep/rules.yml")
        assert SemgrepScanner().ruleset == "/etc/semgrep/rules.yml"

    def test_default_ruleset_is_vendored_offline_dir(self, monkeypatch):
        # NOT "auto": auto is metrics-gated + needs blocked registry egress, so it
        # can never load in-pod. Default to the offline rules baked at build time.
        monkeypatch.delenv("SEMGREP_RULESET", raising=False)
        assert SemgrepScanner().ruleset == "/opt/semgrep-rules"


@pytest.mark.skipif(
    not SemgrepScanner().is_available(),
    reason="semgrep CLI not installed (isolated in the image; absent in the CI venv)",
)
class TestSemgrepLive:
    """Real-CLI proof against the vendored fixture rules — runs locally / in-pod."""

    async def test_live_detects_python_sql_injection(self, tmp_path):
        scanner = SemgrepScanner()
        scanner.ruleset = str(FIXTURE_RULES)
        f = tmp_path / "vuln.py"
        f.write_text('def q(cur, x):\n    cur.execute("SELECT * FROM t WHERE id=" + x)\n')
        matches = await scanner.scan([str(f)])
        sqli = [m for m in matches if m.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].severity == VulnerabilitySeverity.HIGH

    async def test_live_safe_query_not_flagged(self, tmp_path):
        scanner = SemgrepScanner()
        scanner.ruleset = str(FIXTURE_RULES)
        f = tmp_path / "safe.py"
        f.write_text('def q(cur, x):\n    cur.execute("SELECT * FROM t WHERE id=%s", (x,))\n')
        matches = await scanner.scan([str(f)])
        assert [m for m in matches if m.vulnerability_type == VulnerabilityType.SQL_INJECTION] == []
