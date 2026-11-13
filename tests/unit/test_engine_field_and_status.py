"""R216/R215: every scan finding names its engine, and every engine reports a status.

The conveyor flow used to infer "IaC" from an AVD-* rule id and had no per-engine
signal. These tests pin the contract it now reads instead:

* ``result.file_results[].violations[].engine`` (and ``report.top_priorities[].engine``)
  is one of pattern / bandit / semgrep / detect-secrets / trivy-iac /
  trivy-image, set by the engine that produced the finding.
* ``result.engine_status`` is ``{engine: {"status": "ok"|"degraded"|"failed",
  "reason": str|null}}`` and ALWAYS carries all six engines — a missing tool, a
  timeout, a crash, a deadline or an empty scan is never ``ok`` and never omitted.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from models.security_api_models import (
    ContainerSecurityScanRequest,
    ContainerSecurityScanResponse,
    ScanFindingViolation,
)
from services.bandit_scanner import BanditScanner
from services.iac_scanner import IaCScanner
from services.scanner_errors import ScannerExecutionError
from services.secrets_scanner import SecretsScanner
from services.security_detector import (
    SCAN_ENGINES,
    ParseResult,
    ParserType,
    PartialAnalysisState,
    ScanEngine,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from services.security_scan_service import SecurityScanService
from services.semgrep_scanner import SemgrepScanner

from .test_security_scan_service import make_container_info

ALL_ENGINES = {
    "pattern",
    "bandit",
    "semgrep",
    "detect-secrets",
    "trivy-iac",
    "trivy-image",
}


def test_engine_enum_is_the_contract_set():
    assert {str(e) for e in SCAN_ENGINES} == ALL_ENGINES


# --------------------------------------------------------------------------
# Each producer stamps its own engine
# --------------------------------------------------------------------------


def test_bandit_findings_carry_bandit_engine():
    out = BanditScanner()._parse_bandit_json(
        '{"results": [{"filename": "x.py", "line_number": 3, "line_range": [3],'
        ' "issue_severity": "HIGH", "issue_confidence": "HIGH",'
        ' "issue_text": "exec used", "test_id": "B102", "test_name": "exec_used"}]}'
    )
    assert [m.engine for m in out] == ["bandit"]


def test_semgrep_findings_carry_semgrep_engine():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval",
                "path": "x.py",
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {"severity": "ERROR", "message": "eval", "metadata": {}},
            }
        ]
    }
    out = SemgrepScanner()._parse_semgrep_json(json.dumps(payload))
    assert [m.engine for m in out] == ["semgrep"]


def test_detect_secrets_findings_carry_detect_secrets_engine():
    out = SecretsScanner()._parse_secrets_json(
        '{"results": {"x.py": [{"type": "AWS Access Key", "line_number": 5,'
        ' "is_verified": true, "hashed_secret": "abc"}]}}'
    )
    assert [m.engine for m in out] == ["detect-secrets"]


def test_trivy_iac_findings_carry_trivy_iac_engine():
    payload = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "AVDID": "AVD-DS-0002",
                        "Title": "Image user should not be 'root'",
                        "Message": "Specify a non-root USER",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "CauseMetadata": {"StartLine": 1, "EndLine": 1},
                    }
                ],
            }
        ]
    }
    out = IaCScanner()._parse_trivy_config_json(json.dumps(payload))
    assert len(out) == 1
    assert out[0].engine == "trivy-iac"
    assert out[0].pattern_id == "AVD-DS-0002"


@pytest.mark.asyncio
async def test_pattern_findings_carry_pattern_engine():
    svc = SecurityScanService()
    out = await svc.detector.scan_inline('import os\nos.system("rm -rf " + user_input)\n', "python")
    assert out, "the in-process rule set should flag os.system with concatenation"
    assert {m.engine for m in out} == {"pattern"}


def test_scan_violation_rejects_missing_or_unknown_engine():
    base = {
        "type": "sql_injection",
        "severity": "high",
        "pattern_matched": "p",
        "description": "d",
    }
    with pytest.raises(ValidationError):
        ScanFindingViolation.model_validate(base)
    with pytest.raises(ValidationError):
        ScanFindingViolation.model_validate({**base, "engine": ""})
    with pytest.raises(ValidationError):
        ScanFindingViolation.model_validate({**base, "engine": "trivy"})


# --------------------------------------------------------------------------
# Engine wrappers: a crash is a failure, never "ok with zero findings"
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bandit_crash_raises_instead_of_returning_clean(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    scanner = BanditScanner()
    scanner.bandit_available = True
    with (
        patch(
            "services.bandit_scanner.run_subprocess",
            side_effect=RuntimeError("boom"),
        ),
        pytest.raises(ScannerExecutionError),
    ):
        await scanner.scan([str(f)])


# --------------------------------------------------------------------------
# Detector: engine_status per outcome
# --------------------------------------------------------------------------


def _match(engine: str, file_path: str, line: int, vtype=VulnerabilityType.SQL_INJECTION):
    return VulnerabilityMatch(
        id=f"{engine}-{line}",
        vulnerability_type=vtype,
        severity=VulnerabilitySeverity.HIGH,
        confidence=VulnerabilityConfidence.HIGH,
        file_path=file_path,
        language="python",
        line_start=line,
        line_end=line,
        pattern_id=f"{engine}-rule",
        engine=engine,
    )


class _Engine:
    def __init__(self, *, available=True, result=None, exc=None):
        self._available = available
        self._result = result or []
        self._exc = exc

    def is_available(self):
        return self._available

    async def scan(self, _targets, **_kwargs):
        if self._exc is not None:
            raise self._exc
        return list(self._result)


def _detector_with(monkeypatch, codebase: str, *, bandit, semgrep, secrets, iac, image=None):
    detector = SecurityScanService().detector
    target = f"{codebase}/a.py"

    async def _fake_parse(_path):
        return ParseResult(
            success=True,
            file_path=target,
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
        )

    async def _fake_detect(_parsed, _low, _reasons=None):
        return [_match("pattern", target, 1)]

    monkeypatch.setattr(detector, "_parse_file_for_security", _fake_parse)
    monkeypatch.setattr(detector, "_detect_vulnerabilities", _fake_detect)
    monkeypatch.setattr(detector, "_bandit", bandit)
    monkeypatch.setattr(detector, "_semgrep", semgrep)
    monkeypatch.setattr(detector, "_secrets", secrets)
    monkeypatch.setattr(detector, "_iac", iac)
    # Default: a clean base-image engine, so tests that predate it keep the same
    # "every engine ran" state instead of depending on a trivy in the test env.
    monkeypatch.setattr(detector, "_image", image if image is not None else _Engine())
    return detector, target


@pytest.mark.asyncio
async def test_all_engines_ok_and_findings_keep_their_engine(monkeypatch):
    codebase = "/tmp/r216-ok"
    t = f"{codebase}/a.py"
    detector, _ = _detector_with(
        monkeypatch,
        codebase,
        bandit=_Engine(result=[_match("bandit", t, 2)]),
        semgrep=_Engine(result=[_match("semgrep", t, 3)]),
        secrets=_Engine(result=[_match("detect-secrets", t, 4)]),
        iac=_Engine(result=[_match("trivy-iac", t, 5, VulnerabilityType.PRIVILEGE_ESCALATION)]),
        image=_Engine(
            result=[_match("trivy-image", t, 6, VulnerabilityType.VULNERABLE_DEPENDENCY)]
        ),
    )
    result = await detector.analyze_security_vulnerabilities([t])
    assert result.scan_degraded is False
    assert set(result.engine_status) == ALL_ENGINES
    assert all(v == {"status": "ok", "reason": None} for v in result.engine_status.values())
    engines = {m.engine for matches in result.vulnerabilities_by_type.values() for m in matches}
    assert engines == ALL_ENGINES


@pytest.mark.asyncio
async def test_missing_timeout_crash_and_partial_engines_are_never_ok(monkeypatch):
    codebase = "/tmp/r216-bad"
    t = f"{codebase}/a.py"
    detector, _ = _detector_with(
        monkeypatch,
        codebase,
        # CLI not on PATH
        bandit=_Engine(available=False),
        # timed out (wrappers convert TimeoutError to this)
        semgrep=_Engine(exc=ScannerExecutionError("semgrep", -1, "timed out")),
        # unexpected exception escaping the wrapper
        secrets=_Engine(exc=RuntimeError("kaboom")),
        # per-target engine failed after finding something
        iac=_Engine(
            exc=ScannerExecutionError(
                "trivy-iac", 1, "bad target", partial_findings=[_match("trivy-iac", t, 9)]
            )
        ),
    )
    result = await detector.analyze_security_vulnerabilities([t])
    st = result.engine_status
    assert set(st) == ALL_ENGINES
    assert st["pattern"]["status"] == "ok"
    assert st["bandit"]["status"] == "failed"
    assert st["bandit"]["reason"].startswith("tool missing")
    assert st["semgrep"]["status"] == "failed"
    assert "timed out" in st["semgrep"]["reason"]
    assert st["detect-secrets"]["status"] == "failed"
    assert "kaboom" in st["detect-secrets"]["reason"]
    assert st["trivy-iac"]["status"] == "degraded"
    assert result.scan_degraded is True
    # the partial IaC finding survives and still names its engine
    kept = [m for ms in result.vulnerabilities_by_type.values() for m in ms if m.line_start == 9]
    assert [m.engine for m in kept] == ["trivy-iac"]


@pytest.mark.asyncio
async def test_pattern_budget_exhaustion_is_degraded(monkeypatch):
    codebase = "/tmp/r216-budget"
    t = f"{codebase}/a.py"
    detector, _ = _detector_with(
        monkeypatch,
        codebase,
        bandit=_Engine(),
        semgrep=_Engine(),
        secrets=_Engine(),
        iac=_Engine(),
    )

    async def _detect_with_budget_hit(_parsed, _low, reasons=None):
        if reasons is not None:
            reasons.append("long-span check timed out on a.py")
        return []

    monkeypatch.setattr(detector, "_detect_vulnerabilities", _detect_with_budget_hit)
    result = await detector.analyze_security_vulnerabilities([t])
    assert result.engine_status["pattern"]["status"] == "degraded"
    assert "long-span" in result.engine_status["pattern"]["reason"]
    assert result.scan_degraded is True


@pytest.mark.asyncio
async def test_deadline_marks_unfinished_engines_failed():
    detector = SecurityScanService().detector
    partial = PartialAnalysisState()
    partial.engine_status["pattern"] = {"status": "ok", "reason": None}
    partial.engine_status["bandit"] = {"status": "ok", "reason": None}
    result = await detector.result_from_partial(partial)
    st = result.engine_status
    assert set(st) == ALL_ENGINES
    assert st["pattern"]["status"] == "ok"
    assert st["bandit"]["status"] == "ok"
    for e in ("semgrep", "detect-secrets", "trivy-iac", "trivy-image"):
        assert st[e]["status"] == "failed"
        assert "deadline" in st[e]["reason"]


# --------------------------------------------------------------------------
# Service / HTTP response shape
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_response_json_carries_engine_and_engine_status(monkeypatch, tmp_path):
    codebase = str(tmp_path)
    (Path(codebase) / "a.py").write_text("x = 1\n")
    (Path(codebase) / "Dockerfile").write_text("FROM ubuntu\n")
    svc = SecurityScanService()
    _det, _ = _detector_with(
        monkeypatch,
        codebase,
        bandit=_Engine(),
        semgrep=_Engine(),
        secrets=_Engine(exc=ScannerExecutionError("detect-secrets", -1, "timed out")),
        iac=_Engine(
            result=[
                _match(
                    "trivy-iac", f"{codebase}/Dockerfile", 1, VulnerabilityType.PRIVILEGE_ESCALATION
                )
            ]
        ),
    )
    svc.detector = _det
    ci = make_container_info(codebase_path=codebase)
    result = await svc.scan_container(
        ci, ContainerSecurityScanRequest(container_name="test-container")
    )
    body = ContainerSecurityScanResponse(
        status="degraded" if result.scan_degraded else "success", message="m", result=result
    ).model_dump(mode="json")

    violations = [v for fr in body["result"]["file_results"] for v in fr["violations"]]
    assert {v["engine"] for v in violations} == {"pattern", "trivy-iac"}
    iac = [v for v in violations if v["engine"] == "trivy-iac"]
    assert iac and iac[0]["pattern_matched"] == "trivy-iac-rule"

    st = body["result"]["engine_status"]
    assert set(st) == ALL_ENGINES
    assert st["detect-secrets"] == {
        "status": "failed",
        "reason": "engine detect-secrets failed to run: detect-secrets exited -1 "
        "with unparseable output. stderr: timed out",
    }
    assert body["result"]["scan_degraded"] is True
    assert body["result"]["degraded_reasons"]

    report = await svc.generate_security_report(ci, result)
    assert all(v.engine in ALL_ENGINES for v in report.top_priorities)


@pytest.mark.asyncio
async def test_empty_scan_reports_every_engine_failed(tmp_path):
    svc = SecurityScanService()
    ci = make_container_info(codebase_path=str(tmp_path))
    result = await svc.scan_container(
        ci, ContainerSecurityScanRequest(container_name="test-container")
    )
    assert result.scan_degraded is True
    assert set(result.engine_status) == ALL_ENGINES
    assert {s.status for s in result.engine_status.values()} == {"failed"}


def test_scan_engine_values_are_plain_strings():
    assert json.dumps({ScanEngine.TRIVY_IAC: 1}) == '{"trivy-iac": 1}'
