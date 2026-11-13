"""Tests for the real detect-secrets scanner."""

import pytest

from services.scanner_errors import ScannerExecutionError
from services.secrets_scanner import SecretsScanner
from services.security_detector import (
    VulnerabilityConfidence,
    VulnerabilitySeverity,
    VulnerabilityType,
)


@pytest.fixture
def scanner():
    return SecretsScanner()


class TestSecretsScanner:
    def test_secrets_is_available(self, scanner):
        """detect-secrets is a runtime dependency, so it must be present."""
        assert scanner.is_available() is True
        status = scanner.get_status()
        assert status["available"] is True
        assert status["version"]

    async def test_detect_aws_key(self, scanner, tmp_path):
        """An AWS access key literal is detected as a HARDCODED_CREDENTIALS finding."""
        code_file = tmp_path / "config.py"
        # AWS example key written to a runtime temp file (not committed).
        code_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')  # pragma: allowlist secret
        matches = await scanner.scan([str(code_file)])

        assert len(matches) >= 1
        m = matches[0]
        assert m.vulnerability_type == VulnerabilityType.HARDCODED_CREDENTIALS
        # A provider-specific detector (shape of an AWS key id), not a heuristic.
        assert m.severity == VulnerabilitySeverity.CRITICAL
        assert m.confidence == VulnerabilityConfidence.MEDIUM
        assert "CWE-798" in m.cwe_ids
        # Never leak the secret value into the response.
        assert m.code_snippet == ""
        assert m.line_start >= 1

    async def test_clean_file_no_findings(self, scanner, tmp_path):
        code_file = tmp_path / "clean.py"
        code_file.write_text("x = 1 + 2\nprint(x)\n")
        assert await scanner.scan([str(code_file)]) == []

    async def test_empty_paths(self, scanner):
        assert await scanner.scan([]) == []

    async def test_unavailable_returns_empty(self, tmp_path):
        scanner = SecretsScanner()
        scanner.secrets_available = False
        code_file = tmp_path / "config.py"
        code_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')  # pragma: allowlist secret
        assert await scanner.scan([str(code_file)]) == []
        assert scanner.is_available() is False

    def test_parse_empty_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_secrets_json("")

    def test_parse_malformed_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_secrets_json("{not valid json")

    def test_parse_verified_secret_is_high_confidence(self, scanner):
        result = scanner._parse_secrets_json(
            '{"results": {"x.py": [{"type": "AWS Access Key", "line_number": 5,'
            ' "is_verified": true, "hashed_secret": "abc"}]}}'
        )
        assert len(result) == 1
        assert result[0].confidence == VulnerabilityConfidence.HIGH
        assert result[0].pattern_id == "detect-secrets:AWS Access Key"
