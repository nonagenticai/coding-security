"""``_filter_results_by_severity`` must produce an internally-consistent result.

The ``/analyze-vulnerabilities`` endpoint applies ``severity_filter`` as a VIEW
filter over a completed :class:`SecurityAnalysisResult`. Regression guard: every
per-match view (by type / severity / confidence / language) plus the derived
counts, priority fixes, hotspots and most-common type must reflect ONLY the
surviving severities. The pre-fix implementation pruned only ``by_type`` and
``by_severity``, leaving the confidence/language views, ``priority_fixes`` and
the critical/high counts describing the unfiltered scan — a caller filtering to
``["critical"]`` still saw HIGH/LOW vulns in ``vulnerabilities_by_language`` and
a ``critical_issues_count`` that contradicted ``total_vulnerabilities_found``.
"""

from __future__ import annotations

from routers.security._common import _filter_results_by_severity
from services.security_detector import (
    SecurityAnalysisResult,
    VulnerabilitySeverity,
    VulnerabilityType,
)

from .test_security_scan_service import make_vuln_match


def _mixed_result() -> SecurityAnalysisResult:
    """A completed result with CRITICAL / HIGH / LOW findings across dimensions."""
    critical = make_vuln_match(
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        file_path="/repo/crit.py",
    )
    high = make_vuln_match(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.HIGH,
        file_path="/repo/high.py",
        language="java",
    )
    low = make_vuln_match(
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=VulnerabilitySeverity.LOW,
        file_path="/repo/low.js",
        language="javascript",
    )
    all_vulns = [critical, high, low]

    result = SecurityAnalysisResult(
        total_files_analyzed=3,
        total_vulnerabilities_found=len(all_vulns),
        analysis_time_seconds=0.1,
    )
    for v in all_vulns:
        result.vulnerabilities_by_type.setdefault(v.vulnerability_type, []).append(v)
        result.vulnerabilities_by_severity.setdefault(v.severity, []).append(v)
        result.vulnerabilities_by_confidence.setdefault(v.confidence, []).append(v)
        result.vulnerabilities_by_language.setdefault(v.language, []).append(v)
    result.critical_issues_count = 1
    result.high_severity_count = 1
    # priority_fixes holds the CRITICAL + HIGH (HIGH-confidence) findings.
    result.priority_fixes = [critical, high]
    result.most_common_vulnerability = VulnerabilityType.COMMAND_INJECTION
    return result


def test_filter_to_critical_prunes_every_view_and_count():
    result = _mixed_result()

    _filter_results_by_severity(result, ["critical"])

    surviving = [m for matches in result.vulnerabilities_by_type.values() for m in matches]
    assert len(surviving) == 1
    assert all(m.severity == VulnerabilitySeverity.CRITICAL for m in surviving)

    # Counts match the surviving set (no stale unfiltered numbers).
    assert result.total_vulnerabilities_found == 1
    assert result.critical_issues_count == 1
    assert result.high_severity_count == 0

    # No filtered-out vuln leaks into the confidence / language views.
    conf_vulns = [m for ms in result.vulnerabilities_by_confidence.values() for m in ms]
    lang_vulns = [m for ms in result.vulnerabilities_by_language.values() for m in ms]
    assert all(m.severity == VulnerabilitySeverity.CRITICAL for m in conf_vulns)
    assert all(m.severity == VulnerabilitySeverity.CRITICAL for m in lang_vulns)
    # The HIGH finding's language (java) is gone; only the critical file's language remains.
    assert set(result.vulnerabilities_by_language) == {"python"}

    # priority_fixes drops the now-filtered HIGH finding.
    assert all(m.severity == VulnerabilitySeverity.CRITICAL for m in result.priority_fixes)
    assert result.most_common_vulnerability == VulnerabilityType.COMMAND_INJECTION


def test_filter_to_absent_severity_yields_empty_consistent_result():
    result = _mixed_result()

    _filter_results_by_severity(result, ["info"])

    assert result.total_vulnerabilities_found == 0
    assert result.critical_issues_count == 0
    assert result.high_severity_count == 0
    assert result.vulnerabilities_by_type == {}
    assert result.vulnerabilities_by_confidence == {}
    assert result.vulnerabilities_by_language == {}
    assert result.priority_fixes == []
    assert result.most_common_vulnerability is None
