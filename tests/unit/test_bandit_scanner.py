"""Tests for the real bandit source-SAST scanner."""

import pytest

from services.bandit_scanner import BanditScanner
from services.scanner_errors import ScannerExecutionError
from services.security_detector import (
    VulnerabilitySeverity,
    VulnerabilityType,
)


@pytest.fixture
def scanner():
    return BanditScanner()


class TestBanditScanner:
    def test_bandit_is_available(self, scanner):
        """bandit is a runtime dependency, so it must be present in the venv."""
        assert scanner.is_available() is True
        status = scanner.get_status()
        assert status["available"] is True
        assert status["version"]

    async def test_detect_sql_injection(self, scanner, tmp_path):
        """A string-formatted SQL query is flagged by bandit as B608 / SQL_INJECTION."""
        code_file = tmp_path / "vuln.py"
        code_file.write_text(
            "def q(cur, user_id):\n"
            "    cur.execute(\"SELECT * FROM users WHERE id = '%s'\" % user_id)\n"
        )
        matches = await scanner.scan([str(code_file)])

        sqli = [m for m in matches if m.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1
        m = sqli[0]
        assert m.pattern_id == "B608"
        assert m.severity == VulnerabilitySeverity.MEDIUM
        assert "CWE-89" in m.cwe_ids
        assert m.file_path == str(code_file)
        assert m.language == "python"
        assert m.line_start >= 1

    async def test_safe_parameterized_query_not_flagged(self, scanner, tmp_path):
        """The safe psycopg parameterized form is NOT flagged by bandit (no FP)."""
        code_file = tmp_path / "safe.py"
        code_file.write_text(
            "def q(cur, user_id):\n"
            '    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        )
        matches = await scanner.scan([str(code_file)])
        assert [m for m in matches if m.vulnerability_type == VulnerabilityType.SQL_INJECTION] == []

    async def test_detect_hardcoded_password(self, scanner, tmp_path):
        """bandit flags an assigned hardcoded password (B105) as HARDCODED_CREDENTIALS."""
        code_file = tmp_path / "creds.py"
        code_file.write_text('password = "hunter2isnotsafe"\n')  # pragma: allowlist secret
        matches = await scanner.scan([str(code_file)])
        creds = [
            m for m in matches if m.vulnerability_type == VulnerabilityType.HARDCODED_CREDENTIALS
        ]
        assert len(creds) >= 1
        assert creds[0].pattern_id in {"B105", "B106", "B107"}

    async def test_non_python_files_ignored(self, scanner, tmp_path):
        """Non-Python paths are filtered out (bandit only analyses Python)."""
        txt = tmp_path / "notes.txt"
        txt.write_text("cur.execute('SELECT ' + x)\n")
        assert await scanner.scan([str(txt)]) == []

    async def test_unavailable_returns_empty(self, tmp_path):
        """When bandit is absent the scanner degrades gracefully to no findings."""
        scanner = BanditScanner()
        scanner.bandit_available = False
        code_file = tmp_path / "vuln.py"
        code_file.write_text('cur.execute("SELECT " + x)\n')
        assert await scanner.scan([str(code_file)]) == []
        assert scanner.is_available() is False

    def test_parse_empty_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_bandit_json("")

    def test_parse_malformed_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_bandit_json("{not valid json")

    def test_parse_non_dict_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_bandit_json("[1, 2, 3]")

    def test_to_match_unmapped_test_id_falls_back(self, scanner):
        """An unknown bandit test_id maps to INFORMATION_DISCLOSURE, not a crash."""
        result = scanner._parse_bandit_json(
            '{"results": [{"filename": "x.py", "line_number": 3, "line_range": [3],'
            ' "issue_severity": "LOW", "issue_confidence": "HIGH",'
            ' "issue_text": "something", "test_id": "B999", "test_name": "made_up",'
            ' "issue_cwe": {"id": 111}}]}'
        )
        assert len(result) == 1
        assert result[0].vulnerability_type == VulnerabilityType.INFORMATION_DISCLOSURE
        assert result[0].cwe_ids == ["CWE-111"]
        assert result[0].severity == VulnerabilitySeverity.LOW
