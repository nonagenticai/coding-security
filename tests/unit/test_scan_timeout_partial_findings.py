"""Regression tests: a scan timeout must surface partial findings, not discard them.

Background: #62 bounded the container scan with an ``asyncio.wait_for`` deadline and
made the grade coverage-honest (never "A" on zero coverage). But its timeout branch
built a brand-new all-zero result — throwing away every vulnerability the engines
that completed before the deadline had already found. On a large repo that produced
"F, 0 vulns, degraded" when real critical findings existed (weak crypto, hardcoded
passwords, ...). This suite pins the fixed behaviour:

1. ``build_partial_result`` surfaces the accumulated findings, flagged degraded.
2. A zero-progress timeout stays honest (degraded, 0 vulns, NOT a fake "A") — the
   #62 guarantee is preserved.
3. ``_run_scan_bounded`` threads the caller-held accumulator so a mid-scan timeout
   recovers what was found (the accumulator survives the coroutine cancellation).
4. ``analyze_security_vulnerabilities`` populates the accumulator incrementally, so
   there IS partial data to recover at a cancellation point.
"""

import asyncio

import pytest

from models.security_api_models import ContainerSecurityScanRequest
from routers.security import container_scan
from services.security_detector import (
    ParserType,
    PartialAnalysisState,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from services.security_scan_service import SecurityScanService

from .test_security_scan_service import make_container_info, make_vuln_match


def _parsed(file_path: str, language: str = "python"):
    from services.security_detector import ParseResult

    return ParseResult(
        success=True,
        file_path=file_path,
        language=language,
        parser_used=ParserType.REGEX_FALLBACK,
    )


@pytest.mark.asyncio
async def test_build_partial_result_surfaces_findings_not_zero():
    """A populated accumulator → the findings are carried through, flagged degraded.

    This is the crux: before the fix the timeout path returned total=0; now the
    vulnerabilities the completed engines found are surfaced.
    """
    codebase = "/tmp/test-repo"
    ci = make_container_info(codebase_path=codebase)
    critical = make_vuln_match(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        file_path=f"{codebase}/app/db.py",
    )
    partial = PartialAnalysisState(
        parsed_files=[_parsed(f"{codebase}/app/db.py"), _parsed(f"{codebase}/app/util.py")],
        external_matches=[critical],
    )

    svc = SecurityScanService()
    result = await svc.build_partial_result(ci, partial, elapsed_seconds=60.0)

    # Findings preserved — NOT discarded to a fake zero.
    assert result.total_vulnerabilities == 1
    assert result.critical_count == 1
    assert result.total_files_scanned == 2
    assert result.file_results, "partial findings must appear in file_results"
    # Honest about incomplete coverage.
    assert result.scan_degraded is True
    assert result.security_grade == "F"  # degraded → F, but the vuln is now visible
    assert result.scan_duration_seconds == 60.0


@pytest.mark.asyncio
async def test_build_partial_result_zero_progress_is_honest_not_a_pass():
    """A timeout before any finding → degraded, 0 vulns, and NEVER a fake 'A'.

    Preserves the #62 guarantee: a zero-coverage scan must not grade clean.
    """
    ci = make_container_info()
    partial = PartialAnalysisState()  # nothing accumulated

    svc = SecurityScanService()
    result = await svc.build_partial_result(ci, partial, elapsed_seconds=60.0)

    assert result.total_vulnerabilities == 0
    assert result.total_files_scanned == 0
    assert result.scan_degraded is True
    assert result.security_grade != "A"
    assert result.security_grade == "F"


@pytest.mark.asyncio
async def test_run_scan_bounded_recovers_partial_on_timeout(monkeypatch):
    """The router's bounded scan recovers findings the scan made before the deadline.

    ``scan_container`` populates the caller-held ``partial`` then hangs; the tiny
    budget forces a timeout; the returned result must carry the finding (proving the
    accumulator survived the wait_for cancellation and was read on the timeout path).
    """
    from config import settings as settings_mod

    settings_mod.get_settings.cache_clear()
    monkeypatch.setenv("SECURITY_SCAN_BUDGET_SECONDS", "0.05")

    codebase = "/tmp/test-repo"
    ci = make_container_info(codebase_path=codebase)
    req = ContainerSecurityScanRequest(container_name="test-container")

    async def _populate_then_hang(_ci, _req, *, partial, deadline=None, force_degraded=False):
        # `deadline` is threaded by _run_scan_bounded for the base-image engine;
        # this fake does not use it.
        partial.parsed_files.append(_parsed(f"{codebase}/app/db.py"))
        partial.external_matches.append(
            make_vuln_match(
                severity=VulnerabilitySeverity.CRITICAL,
                file_path=f"{codebase}/app/db.py",
            )
        )
        await asyncio.sleep(5)  # exceed the 0.05s budget

    svc = SecurityScanService()
    monkeypatch.setattr(svc, "scan_container", _populate_then_hang)

    result = await container_scan._run_scan_bounded(svc, ci, req, "test-container")

    assert result.scan_degraded is True
    assert result.total_vulnerabilities == 1  # NOT discarded to 0
    assert result.critical_count == 1
    assert result.total_files_scanned == 1
    settings_mod.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_analyze_populates_accumulator_incrementally(monkeypatch):
    """analyze_security_vulnerabilities fills ``partial`` so a cancellation has data.

    Parsing and regex detection are stubbed to deterministic values (no real files,
    no SAST CLIs); we assert the accumulator ends up holding what the returned result
    reflects — i.e. at any await point after these steps the caller-held ``partial``
    already carries the findings.
    """
    detector = SecurityScanService().detector

    match = VulnerabilityMatch(
        engine="pattern",
        id="v1",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.HIGH,
        confidence=VulnerabilityConfidence.HIGH,
        file_path="/tmp/test-repo/a.py",
        language="python",
        line_start=1,
        line_end=1,
    )

    async def _fake_parse(_path):
        return _parsed("/tmp/test-repo/a.py")

    async def _fake_detect(_parsed_files, _low, _degraded_reasons=None):
        return [match]

    monkeypatch.setattr(detector, "_parse_file_for_security", _fake_parse)
    monkeypatch.setattr(detector, "_detect_vulnerabilities", _fake_detect)
    # Force all augmentation engines unavailable → deterministic, external stays [].
    for engine in (detector._bandit, detector._semgrep, detector._secrets, detector._iac):
        monkeypatch.setattr(engine, "is_available", lambda: False)

    partial = PartialAnalysisState()
    result = await detector.analyze_security_vulnerabilities(
        file_paths=["/tmp/test-repo/a.py"], partial=partial
    )

    assert len(partial.parsed_files) == 1
    assert partial.regex_matches == [match]
    assert partial.include_low_confidence is True
    # The accumulator reflects the same finding the full result reports.
    assert result.total_vulnerabilities_found == 1
