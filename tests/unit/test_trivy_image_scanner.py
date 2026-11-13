"""Tests for the base-image OS-CVE engine (``trivy image``)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from models.architecture_models import Vulnerability
from services.scanner_errors import ScannerExecutionError, ScannerPartialRunError
from services.security_detector import (
    SecurityVulnerabilityDetector,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from services.trivy_image_scanner import (
    TrivyImageScanner,
    extract_base_images,
    is_dockerfile,
    resolve_image_ref,
)

REGISTRY = "mirror.example.com"

_TRIVY_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": f"{REGISTRY}/library/python:3.12-slim-bookworm",
    "Results": [
        {
            "Class": "os-pkgs",
            "Target": f"{REGISTRY}/library/python:3.12-slim-bookworm (debian 12.15)",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-109518",
                    "PkgName": "apt",
                    "InstalledVersion": "2.6.1",
                    "FixedVersion": "2.6.2",
                    "Severity": "HIGH",
                    "Title": "On-path attacker can install packages",
                    "Description": "apt before 2.6.2 is vulnerable.",
                    "PublishedDate": "2026-09-01T00:00:00Z",
                    "LastModifiedDate": "2026-10-01T00:00:00Z",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-109518",
                    "References": ["https://security-tracker.debian.org/CVE-2026-109518"],
                },
                {
                    "VulnerabilityID": "CVE-2011-3374",
                    "PkgName": "apt",
                    "InstalledVersion": "2.6.1",
                    "Severity": "LOW",
                    "Title": "Not exploitable in practice",
                },
            ],
        },
        {
            # Language packages are the dependency scan's job; they must NOT be
            # reported a second time by this engine.
            "Class": "lang-pkgs",
            "Target": "Python",
            "Type": "python-pkg",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2020-0001",
                    "PkgName": "requests",
                    "InstalledVersion": "2.0.0",
                    "FixedVersion": "2.1.0",
                    "Severity": "CRITICAL",
                }
            ],
        },
    ],
}


def _scanner(monkeypatch, *, report=_TRIVY_REPORT, returncode=0, captured=None):
    scanner = TrivyImageScanner()
    scanner.trivy_available = True

    async def _fake_run(cmd, **kwargs):
        if captured is not None:
            captured.append(cmd)
        return returncode, json.dumps(report), ""

    monkeypatch.setattr("services.trivy_image_scanner.run_subprocess", _fake_run)
    monkeypatch.setattr(TrivyImageScanner, "_registry", staticmethod(lambda: REGISTRY))
    return scanner


def _iso_days_ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Dockerfile parsing
# --------------------------------------------------------------------------


def test_is_dockerfile_names():
    assert is_dockerfile("/repo/Dockerfile")
    assert is_dockerfile("/repo/Dockerfile.prod")
    assert is_dockerfile("/repo/dockerfile-dev")
    assert is_dockerfile("/repo/app.Dockerfile")
    assert is_dockerfile("/repo/Containerfile")
    assert is_dockerfile("/repo/Containerfile.prod")
    assert is_dockerfile("/repo/app.containerfile")
    assert not is_dockerfile("/repo/docker-compose.yml")
    assert not is_dockerfile("/repo/README.md")


def test_comment_continuation_does_not_swallow_the_from():
    """Docker strips comments BEFORE joining continuations.

    A ``# ... \\`` line is a comment, not the start of a continuation. The old
    join-first parser swallowed the next line, so this exact Dockerfile yielded
    no refs and no problems — engine ok, base image never scanned.
    """
    text = "# base image is pinned to bookworm \\\nFROM python:3.12-slim-bookworm\n"
    refs, problems = extract_base_images(text)
    assert problems == []
    assert [(r.image, r.line) for r in refs] == [("python:3.12-slim-bookworm", 2)]


def test_comment_inside_a_from_continuation_is_ignored():
    text = (
        "FROM --platform=linux/amd64 \\\n"
        "# pinned for the toolchain; the backslash above continues past me \\\n"
        "    python:3.12-slim\n"
    )
    refs, problems = extract_base_images(text)
    assert problems == []
    assert [(r.image, r.line) for r in refs] == [("python:3.12-slim", 1)]


def test_quoted_arg_defaults_are_unquoted():
    for default in ('"python:3.12-slim"', "'python:3.12-slim'"):
        refs, problems = extract_base_images(f"ARG BASE={default}\nFROM ${{BASE}}\n")
        assert problems == []
        assert refs[0].image == "python:3.12-slim"


def test_extract_multi_stage_reports_only_the_final_stage_base():
    # openplanner's real shape: uv + node builder stages, a python build stage
    # and a python runtime stage. Only the LAST stage ships, so only its base
    # image is scanned — the builder images' OS packages never reach the image.
    text = """# syntax=docker/dockerfile:1
ARG BASE_REGISTRY=docker.io
FROM ${BASE_REGISTRY}/library/python:3.12-slim AS builder
RUN pip install x
FROM --platform=linux/amd64 ${BASE_REGISTRY}/library/node:22-alpine AS web
FROM builder AS final
FROM ${BASE_REGISTRY}/library/python:3.12-slim AS runtime
RUN true
"""
    refs, problems = extract_base_images(text)
    assert problems == []
    assert [(r.image, r.line, r.stage_alias) for r in refs] == [
        ("docker.io/library/python:3.12-slim", 7, "runtime")
    ]
    # The continuation-free FROM is reported on its physical line.
    assert refs[0].line_text.startswith("FROM ${BASE_REGISTRY}")


def test_extract_final_stage_from_alias_resolves_to_the_real_base():
    # The final stage inherits an earlier stage: the base that ships is that
    # stage's image, so the finding is attributed to where it is declared.
    text = "FROM python:3.12-slim AS build\nFROM build AS runtime\n"
    refs, problems = extract_base_images(text)
    assert problems == []
    assert [(r.image, r.line, r.stage_alias) for r in refs] == [("python:3.12-slim", 1, "build")]


def test_extract_final_stage_scratch_scans_nothing():
    text = "FROM python:3.11 AS build\nFROM scratch\n"
    refs, problems = extract_base_images(text)
    assert (refs, problems) == ([], [])


def test_extract_arg_without_default_is_reported_not_guessed():
    text = "FROM ${BASE_IMAGE}\n"
    refs, problems = extract_base_images(text)
    assert refs == []
    assert problems and "BASE_IMAGE" in problems[0]


def test_extract_digest_and_repeated_image_reports_the_final_from():
    text = "FROM python@sha256:" + "a" * 64 + "\nFROM python@sha256:" + "a" * 64 + "\n"
    refs, problems = extract_base_images(text)
    assert problems == []
    assert [r.line for r in refs] == [2]
    assert refs[0].image.endswith("@sha256:" + "a" * 64)


# --------------------------------------------------------------------------
# Ref resolution through the reachable registry
# --------------------------------------------------------------------------


def test_resolve_docker_hub_official_image():
    assert resolve_image_ref("python:3.12-slim", REGISTRY).ref == (
        f"{REGISTRY}/library/python:3.12-slim"
    )
    # docker.io/ prefix is stripped, no double `library/`.
    assert resolve_image_ref("docker.io/library/python:3.12-slim", REGISTRY).ref == (
        f"{REGISTRY}/library/python:3.12-slim"
    )
    # No tag -> trivy's implied :latest, left implicit.
    assert resolve_image_ref("ubuntu", REGISTRY).ref == f"{REGISTRY}/library/ubuntu"


def test_resolve_path_and_digest():
    assert resolve_image_ref("myorg/app:1.2", REGISTRY).ref == f"{REGISTRY}/myorg/app:1.2"
    digest = "sha256:" + "b" * 64
    assert resolve_image_ref(f"debian@{digest}", REGISTRY).ref == (
        f"{REGISTRY}/library/debian@{digest}"
    )
    # An already-internal ref is used unchanged.
    assert resolve_image_ref(f"{REGISTRY}/library/nginx:1.27", REGISTRY).ref == (
        f"{REGISTRY}/library/nginx:1.27"
    )


def test_resolve_rejects_registry_the_pod_cannot_reach():
    resolved = resolve_image_ref("ghcr.io/astral-sh/uv:0.10.10", REGISTRY)
    assert resolved.ref is None
    assert "ghcr.io" in resolved.reason


# --------------------------------------------------------------------------
# Canned trivy JSON -> Vulnerability rows / scan findings
# --------------------------------------------------------------------------


def test_parse_os_vulnerabilities_maps_the_architecture_model():
    from services.trivy_image_scanner import _parse_os_vulnerabilities

    rows = _parse_os_vulnerabilities(_TRIVY_REPORT, "image")
    assert len(rows) == 2  # the lang-pkgs CRITICAL is not this engine's finding
    assert all(isinstance(r, Vulnerability) for r in rows)
    apt = next(r for r in rows if r.id == "CVE-2026-109518")
    assert apt.package_name == "apt"
    assert apt.package_version == "2.6.1"
    assert apt.fixed_versions == ["2.6.2"]
    assert apt.severity == "HIGH"
    assert apt.references[0] == "https://avd.aquasec.com/nvd/cve-2026-109518"
    unfixed = next(r for r in rows if r.id == "CVE-2011-3374")
    assert unfixed.fixed_versions == []


@pytest.mark.asyncio
async def test_scan_maps_findings_to_the_engine_finding_list(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG BASE=python:3.12-slim\nFROM ${BASE} AS runtime\nRUN true\n", encoding="utf-8"
    )
    captured: list[list[str]] = []
    scanner = _scanner(monkeypatch, captured=captured)
    coverage: list[dict] = []

    matches = await scanner.scan([str(dockerfile), str(tmp_path / "app.py")], coverage_out=coverage)

    assert coverage == [
        {
            "ref": "python:3.12-slim",
            "dockerfile": str(dockerfile),
            "line": 2,
            "status": "scanned",
            "error": None,
        }
    ]
    assert len(matches) == 2
    high = next(m for m in matches if m.pattern_id == "CVE-2026-109518")
    assert high.engine == "trivy-image"
    assert high.file_path == str(dockerfile)
    assert high.line_start == 2 and high.line_end == 2
    assert high.code_snippet.startswith("FROM ${BASE}")
    assert high.severity == VulnerabilitySeverity.HIGH
    assert high.vulnerability_type == VulnerabilityType.VULNERABLE_DEPENDENCY
    assert high.context_evidence["package"] == "apt"
    assert high.context_evidence["installed_version"] == "2.6.1"
    assert high.context_evidence["fixed_version"] == "2.6.2"
    assert "2.6.2" in high.remediation_advice
    # Structured fields for consumers: no description parsing required.
    assert high.package_name == "apt"
    assert high.installed_version == "2.6.1"
    assert high.fixed_version == "2.6.2"
    assert high.fix_available is True
    assert high.image_ref == "python:3.12-slim"
    unfixed = next(m for m in matches if m.pattern_id == "CVE-2011-3374")
    assert unfixed.fixed_version == ""
    assert unfixed.fix_available is False
    # One trivy invocation for the one unique base ref, through the mirror.
    assert len(captured) == 1
    assert captured[0][-1] == f"{REGISTRY}/library/python:3.12-slim"


@pytest.mark.asyncio
async def test_scan_without_dockerfile_is_a_complete_noop(monkeypatch, tmp_path):
    scanner = _scanner(monkeypatch)
    assert await scanner.scan([str(tmp_path / "app.py")]) == []


@pytest.mark.asyncio
async def test_scan_only_scratch_is_a_noop(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    scanner = _scanner(monkeypatch)
    assert await scanner.scan([str(dockerfile)]) == []


@pytest.mark.asyncio
async def test_unreachable_registry_fails_loudly(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM ghcr.io/astral-sh/uv:0.10.10\n", encoding="utf-8")
    scanner = _scanner(monkeypatch)
    coverage: list[dict] = []
    with pytest.raises(ScannerExecutionError) as exc:
        await scanner.scan([str(dockerfile)], coverage_out=coverage)
    assert "ghcr.io" in str(exc.value)
    assert len(coverage) == 1
    assert coverage[0]["status"] == "unresolved"
    assert "ghcr.io" in coverage[0]["error"]


@pytest.mark.asyncio
async def test_partial_run_keeps_findings_from_the_image_that_worked(monkeypatch, tmp_path):
    good = tmp_path / "Dockerfile"
    good.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    bad = tmp_path / "app.Dockerfile"
    bad.write_text("FROM ghcr.io/other/base:1\n", encoding="utf-8")

    scanner = _scanner(monkeypatch)
    coverage: list[dict] = []
    with pytest.raises(ScannerPartialRunError) as exc:
        await scanner.scan([str(good), str(bad)], coverage_out=coverage)
    assert [m.pattern_id for m in exc.value.partial_findings] == [
        "CVE-2026-109518",
        "CVE-2011-3374",
    ]
    # The scanned image is reported scanned; the unreachable one is unresolved
    # with its reason — the structured form of the old prose-only degrade.
    by_ref = {row["ref"]: row for row in coverage}
    assert by_ref["python:3.12-slim"]["status"] == "scanned"
    assert by_ref["python:3.12-slim"]["error"] is None
    assert by_ref["ghcr.io/other/base:1"]["status"] == "unresolved"
    assert "ghcr.io" in by_ref["ghcr.io/other/base:1"]["error"]


@pytest.mark.asyncio
async def test_trivy_failure_for_one_image_is_reported(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    scanner = _scanner(monkeypatch, report={}, returncode=1)
    with pytest.raises(ScannerExecutionError):
        await scanner.scan([str(dockerfile)])


# --------------------------------------------------------------------------
# DB handling
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_baked_db_is_used_without_network(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    (cache / "db").mkdir(parents=True)
    (cache / "db" / "trivy.db").write_bytes(b"x")
    (cache / "db" / "metadata.json").write_text(
        json.dumps({"Version": 2, "UpdatedAt": _iso_days_ago(1)}), encoding="utf-8"
    )
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    captured: list[list[str]] = []
    scanner = _scanner(monkeypatch, captured=captured)

    await scanner.scan([str(dockerfile)])

    cmd = captured[0]
    assert "--skip-db-update" in cmd
    assert "--skip-java-db-update" in cmd
    assert cmd[cmd.index("--cache-dir") + 1] == str(cache)


@pytest.mark.asyncio
async def test_stale_baked_db_degrades_with_a_precise_reason(monkeypatch, tmp_path):
    """A baked DB from 20 days ago silently under-reports CVEs: degrade."""
    cache = tmp_path / "cache"
    (cache / "db").mkdir(parents=True)
    (cache / "db" / "trivy.db").write_bytes(b"x")
    (cache / "db" / "metadata.json").write_text(
        json.dumps({"Version": 2, "UpdatedAt": _iso_days_ago(20)}), encoding="utf-8"
    )
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    scanner = _scanner(monkeypatch)

    with pytest.raises(ScannerPartialRunError) as exc:
        await scanner.scan([str(dockerfile)])

    message = str(exc.value)
    assert "days old" in message and "max 10" in message
    # Findings are still carried: stale, not thrown away.
    assert len(exc.value.partial_findings) == 2


@pytest.mark.asyncio
async def test_unreadable_db_metadata_degrades(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    (cache / "db").mkdir(parents=True)
    (cache / "db" / "trivy.db").write_bytes(b"x")  # no metadata.json
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    scanner = _scanner(monkeypatch)

    with pytest.raises(ScannerPartialRunError) as exc:
        await scanner.scan([str(dockerfile)])

    assert "metadata is unreadable" in str(exc.value)


@pytest.mark.asyncio
async def test_base_image_cap_is_reported(monkeypatch, tmp_path):
    paths: list[str] = []
    for index in range(11):
        dockerfile = tmp_path / f"Dockerfile{index}"
        dockerfile.write_text(f"FROM python:3.12-slim-{index}\n", encoding="utf-8")
        paths.append(str(dockerfile))
    scanner = _scanner(monkeypatch)

    with pytest.raises(ScannerPartialRunError) as exc:
        await scanner.scan(paths)

    assert "bounded to 10" in str(exc.value)
    assert len(exc.value.partial_findings) == 20  # 10 scanned images x 2 CVEs


@pytest.mark.asyncio
async def test_without_baked_db_trivy_may_update(monkeypatch, tmp_path):
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "empty-cache"))
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    captured: list[list[str]] = []
    scanner = _scanner(monkeypatch, captured=captured)

    await scanner.scan([str(dockerfile)])

    assert "--skip-db-update" not in captured[0]
    assert captured[0][captured[0].index("--cache-dir") + 1] == str(tmp_path / "empty-cache")


# --------------------------------------------------------------------------
# Budget: the engine never outlives the scan deadline
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_scan_deadline_degrades_without_running_trivy(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    captured: list[list[str]] = []
    scanner = _scanner(monkeypatch, captured=captured)

    with pytest.raises(ScannerPartialRunError) as exc:
        await scanner.scan([str(dockerfile)], deadline=asyncio.get_running_loop().time() - 1)

    assert captured == []  # no trivy was started
    assert "scan deadline reached" in str(exc.value)


@pytest.mark.asyncio
async def test_per_image_timeout_never_exceeds_the_remaining_deadline(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    timeouts: list[float] = []
    scanner = TrivyImageScanner()
    scanner.trivy_available = True

    async def _fake_run(cmd, **kwargs):
        timeouts.append(kwargs["timeout"])
        return 0, json.dumps(_TRIVY_REPORT), ""

    monkeypatch.setattr("services.trivy_image_scanner.run_subprocess", _fake_run)
    monkeypatch.setattr(TrivyImageScanner, "_registry", staticmethod(lambda: REGISTRY))

    await scanner.scan([str(dockerfile)], deadline=asyncio.get_running_loop().time() + 10)

    # 10s left - 5s margin => at most ~5s handed to the subprocess (never 180).
    assert timeouts and 0 < timeouts[0] <= 5.5


@pytest.mark.asyncio
async def test_image_timeout_is_degraded_not_failed(monkeypatch, tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    scanner = TrivyImageScanner()
    scanner.trivy_available = True

    async def _timeout(cmd, **kwargs):
        raise TimeoutError

    monkeypatch.setattr("services.trivy_image_scanner.run_subprocess", _timeout)
    monkeypatch.setattr(TrivyImageScanner, "_registry", staticmethod(lambda: REGISTRY))

    # ScannerPartialRunError is what the detector maps to engine status
    # `degraded`; a budget timeout must never surface as `failed`.
    with pytest.raises(ScannerPartialRunError) as exc:
        await scanner.scan([str(dockerfile)])
    assert "timed out" in str(exc.value)


# --------------------------------------------------------------------------
# The merge must not collapse the CVEs of one FROM line into a single finding
# --------------------------------------------------------------------------


def test_merge_keeps_multiple_trivy_image_findings():
    from services.security_detector import VulnerabilityConfidence, VulnerabilityMatch

    detector = SecurityVulnerabilityDetector()

    def _m(cve: str) -> VulnerabilityMatch:
        return VulnerabilityMatch(
            id=f"trivy_image_{cve}_apt_3",
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=VulnerabilitySeverity.HIGH,
            confidence=VulnerabilityConfidence.HIGH,
            file_path="/repo/Dockerfile",
            language="dockerfile",
            line_start=3,
            line_end=3,
            pattern_id=cve,
            engine="trivy-image",
        )

    merged = detector._merge_matches([], [_m("CVE-1"), _m("CVE-2")], True)
    assert {m.pattern_id for m in merged} == {"CVE-1", "CVE-2"}


def test_merge_still_collapses_two_findings_from_another_engine():
    """The un-collapse is scoped to trivy-image: two semgrep rules on one line
    keep today's single-finding behaviour."""
    from services.security_detector import VulnerabilityConfidence, VulnerabilityMatch

    detector = SecurityVulnerabilityDetector()

    def _m(rule: str, severity: VulnerabilitySeverity) -> VulnerabilityMatch:
        return VulnerabilityMatch(
            id=rule,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=severity,
            confidence=VulnerabilityConfidence.HIGH,
            file_path="/repo/x.py",
            language="python",
            line_start=5,
            line_end=5,
            pattern_id=rule,
            engine="semgrep",
            code_snippet="cur.execute('...' + x)",
        )

    merged = detector._merge_matches(
        [],
        [_m("rule-a", VulnerabilitySeverity.MEDIUM), _m("rule-b", VulnerabilitySeverity.HIGH)],
        True,
    )
    assert len(merged) == 1
    assert merged[0].pattern_id == "rule-b"  # higher severity wins


def test_finding_engine_is_part_of_the_api_contract():
    """A trivy-image finding must serialize: the response model's engine
    Literal is a closed set, so a missing value would 500 a real scan."""
    from models.security_api_models import ScanFindingViolation

    violation = ScanFindingViolation(
        engine="trivy-image",
        type=VulnerabilityType.VULNERABLE_DEPENDENCY.value,
        severity="high",
        line_number=1,
        pattern_matched="CVE-2026-109518",
        description="apt 2.6.1 -> 2.6.2",
    )
    assert violation.engine == "trivy-image"
