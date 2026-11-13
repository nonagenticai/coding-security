"""R216: an engine reports ``ok`` ONLY for a complete, well-formed run.

A validator showed that a fake ``bandit`` on PATH printing garbage, nothing,
``null`` or a report with ``errors[]`` all came out as ``engine_status.bandit =
ok`` with nothing in ``degraded_reasons`` — the wrappers raised only on
``rc != 0 and not parseable`` and their lenient parsers turned anything else
into "zero findings". A degraded or failed engine must BLOCK the conveyor's
security_analysis card (George, 2026-10-14), so every engine is driven here,
through the REAL wrapper and the REAL detector (only the subprocess is faked),
across each output class, and the exact status is asserted.

Status rules under test:

* failed   — exit code not in the tool's documented success/findings set; empty
             stdout; non-JSON; JSON that is not an object (``null``, list);
             an object missing a key the tool always emits.
* degraded — a well-formed report in which the tool itself says the run was
             partial (bandit/semgrep ``errors[]``); findings are kept.
* ok       — a well-formed, complete report (clean or with findings).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from services.bandit_scanner import BanditScanner
from services.iac_scanner import IaCScanner
from services.secrets_scanner import SecretsScanner
from services.security_detector import ParseResult, ParserType
from services.security_scan_service import SecurityScanService
from services.semgrep_scanner import SemgrepScanner

# --------------------------------------------------------------------------
# Real report shapes (measured; see the comments at each wrapper's
# _REQUIRED_KEYS for the tool version each was taken from)
# --------------------------------------------------------------------------

_BANDIT_RESULT = {
    "filename": "PLACEHOLDER",
    "line_number": 2,
    "line_range": [2],
    "issue_severity": "HIGH",
    "issue_confidence": "HIGH",
    "issue_text": "Starting a process with a shell",
    "test_id": "B605",
    "test_name": "start_process_with_a_shell",
}
_BANDIT_ERROR = {"filename": "./b.py", "reason": "syntax error while parsing AST from file"}


def _bandit(results=(), errors=()):
    return json.dumps(
        {
            "errors": list(errors),
            "generated_at": "2026-10-15T00:00:00Z",
            "metrics": {},
            "results": list(results),
        }
    )


_SEMGREP_RESULT = {
    "check_id": "python.lang.security.audit.os-system",
    "path": "PLACEHOLDER",
    "start": {"line": 2},
    "end": {"line": 2},
    "extra": {"severity": "ERROR", "message": "os.system", "metadata": {}},
}
_SEMGREP_ERROR = {"level": "warn", "type": "Syntax error", "message": "could not parse b.js"}


def _semgrep(results=(), errors=()):
    return json.dumps(
        {
            "version": "1.181.0",
            "results": list(results),
            "errors": list(errors),
            "paths": {"scanned": ["a.py"]},
            "skipped_rules": [],
        }
    )


def _secrets(results=None):
    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [],
            "filters_used": [],
            "results": results or {},
            "generated_at": "2026-10-15T00:00:00Z",
        }
    )


_DS_FINDING = {
    "type": "AWS Access Key",
    "filename": "a.py",
    "hashed_secret": "0" * 40,  # pragma: allowlist secret
    "is_verified": False,
    "line_number": 1,
}


def _trivy(results=None, *, omit_results=False):
    report: dict = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.69.3"},
        "ReportID": "r",
        "CreatedAt": "2026-10-15T00:00:00Z",
        "ArtifactName": "Dockerfile",
        "ArtifactType": "filesystem",
    }
    if not omit_results:
        report["Results"] = results if results is not None else []
    return json.dumps(report)


_TRIVY_CLEAN_RESULT = {
    "Target": "Dockerfile",
    "Class": "config",
    "Type": "dockerfile",
    "MisconfSummary": {"Successes": 27, "Failures": 0},
}
_TRIVY_FAIL_RESULT = {
    "Target": "Dockerfile",
    "Class": "config",
    "Type": "dockerfile",
    "MisconfSummary": {"Successes": 23, "Failures": 1},
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

# engine -> (module whose run_subprocess is faked, target file name, scanner factory)
_ENGINES = {
    "bandit": ("services.bandit_scanner", "a.py"),
    "semgrep": ("services.semgrep_scanner", "a.py"),
    "detect-secrets": ("services.secrets_scanner", "a.py"),
    "trivy-iac": ("services.iac_scanner", "Dockerfile"),
}

# (engine, case id, exit code, stdout, expected status, expected finding count)
CASES = [
    # ---- bandit: 0 = clean, 1 = issues found; anything else is not success
    ("bandit", "garbage", 0, "not json at all", "failed", 0),
    ("bandit", "empty", 0, "", "failed", 0),
    ("bandit", "null", 0, "null", "failed", 0),
    ("bandit", "list", 1, "[1, 2, 3]", "failed", 0),
    ("bandit", "wrong-shape dict", 0, json.dumps({"foo": 1}), "failed", 0),
    ("bandit", "results not a list", 0, json.dumps({"results": {}, "errors": []}), "failed", 0),
    ("bandit", "tool errors[]", 0, _bandit(errors=[_BANDIT_ERROR]), "degraded", 0),
    (
        "bandit",
        "tool errors[] + findings",
        1,
        _bandit(results=[_BANDIT_RESULT], errors=[_BANDIT_ERROR]),
        "degraded",
        1,
    ),
    ("bandit", "unexpected exit 2 + valid report", 2, _bandit(), "failed", 0),
    ("bandit", "valid clean", 0, _bandit(), "ok", 0),
    ("bandit", "valid with findings (exit 1)", 1, _bandit(results=[_BANDIT_RESULT]), "ok", 1),
    # ---- semgrep (no --error): 0 is the only success; 2/7 still print JSON
    ("semgrep", "garbage", 0, "Traceback (most recent call last):", "failed", 0),
    ("semgrep", "empty", 0, "", "failed", 0),
    ("semgrep", "null", 0, "null", "failed", 0),
    ("semgrep", "wrong-shape dict", 0, json.dumps({"results": []}), "failed", 0),
    ("semgrep", "tool errors[]", 0, _semgrep(errors=[_SEMGREP_ERROR]), "degraded", 0),
    (
        "semgrep",
        "tool errors[] + findings",
        0,
        _semgrep(results=[_SEMGREP_RESULT], errors=[_SEMGREP_ERROR]),
        "degraded",
        1,
    ),
    (
        "semgrep",
        "unexpected exit 7 (missing ruleset) + valid report",
        7,
        _semgrep(errors=[{"level": "error", "type": "SemgrepError", "message": "no config"}]),
        "failed",
        0,
    ),
    ("semgrep", "unexpected exit 1 + valid report", 1, _semgrep(), "failed", 0),
    ("semgrep", "valid clean", 0, _semgrep(), "ok", 0),
    ("semgrep", "valid with findings", 0, _semgrep(results=[_SEMGREP_RESULT]), "ok", 1),
    # ---- detect-secrets: 0 only; its report has no errors field (see wrapper)
    ("detect-secrets", "garbage", 0, "oops", "failed", 0),
    ("detect-secrets", "empty", 0, "", "failed", 0),
    ("detect-secrets", "null", 0, "null", "failed", 0),
    ("detect-secrets", "wrong-shape dict", 0, json.dumps({"results": []}), "failed", 0),
    ("detect-secrets", "unexpected exit 1 + valid report", 1, _secrets(), "failed", 0),
    ("detect-secrets", "valid clean", 0, _secrets(), "ok", 0),
    (
        "detect-secrets",
        "valid with findings",
        0,
        _secrets({"a.py": [_DS_FINDING]}),
        "ok",
        1,
    ),
    # ---- trivy config (no --exit-code): 0 only; Results omitted = nothing detected
    ("trivy-iac", "garbage", 0, "FATAL", "failed", 0),
    ("trivy-iac", "empty", 0, "", "failed", 0),
    ("trivy-iac", "null", 0, "null", "failed", 0),
    (
        "trivy-iac",
        "wrong-shape dict (no SchemaVersion)",
        0,
        json.dumps({"Results": []}),
        "failed",
        0,
    ),
    (
        "trivy-iac",
        "SchemaVersion is a bool",
        0,
        json.dumps({"SchemaVersion": True, "Results": []}),
        "failed",
        0,
    ),
    (
        "trivy-iac",
        "Results not a list",
        0,
        json.dumps({"SchemaVersion": 2, "Results": {}}),
        "failed",
        0,
    ),
    ("trivy-iac", "unexpected exit 1 + valid report", 1, _trivy([_TRIVY_FAIL_RESULT]), "failed", 0),
    ("trivy-iac", "valid clean", 0, _trivy([_TRIVY_CLEAN_RESULT]), "ok", 0),
    # DELIBERATELY CHANGED (fail-open fix): a Dockerfile report with no Results
    # means trivy did NOT analyse it (measured: malformed manifests/compose files
    # produce rc 0 + `Results` omitted), so it is degraded — never ok. A genuine
    # clean carries a Result with MisconfSummary (the case above).
    ("trivy-iac", "valid, no config detected", 0, _trivy(omit_results=True), "degraded", 0),
    ("trivy-iac", "valid with findings", 0, _trivy([_TRIVY_FAIL_RESULT]), "ok", 1),
]


class _OkEngine:
    def is_available(self):
        return True

    async def scan(self, _targets, **_kwargs):
        return []


def _real_scanner(engine: str):
    if engine == "bandit":
        s = BanditScanner.__new__(BanditScanner)
        s.bandit_available = True
        s.bandit_version = "1.9.4"
    elif engine == "semgrep":
        s = SemgrepScanner.__new__(SemgrepScanner)
        s.semgrep_available = True
        s.semgrep_version = None
        s.ruleset = "/opt/semgrep-rules"
        s._state_dir = None
    elif engine == "detect-secrets":
        s = SecretsScanner.__new__(SecretsScanner)
        s.secrets_available = True
        s.secrets_version = "1.5.0"
    else:
        s = IaCScanner.__new__(IaCScanner)
        s.trivy_available = True
    return s


_ATTR = {
    "bandit": "_bandit",
    "semgrep": "_semgrep",
    "detect-secrets": "_secrets",  # pragma: allowlist secret
    "trivy-iac": "_iac",
    "trivy-image": "_image",
}


async def _run_through_detector(monkeypatch, tmp_path: Path, engine: str, rc: int, stdout: str):
    module, fname = _ENGINES[engine]
    target = tmp_path / fname
    target.write_text("import os\nos.system('ls ' + x)\n")
    detector = SecurityScanService().detector

    async def _fake_parse(path):
        return ParseResult(
            success=True,
            file_path=str(path),
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
        )

    async def _no_pattern_findings(_parsed, _low, _reasons=None):
        return []

    monkeypatch.setattr(detector, "_parse_file_for_security", _fake_parse)
    monkeypatch.setattr(detector, "_detect_vulnerabilities", _no_pattern_findings)
    for name, attr in _ATTR.items():
        monkeypatch.setattr(detector, attr, _real_scanner(name) if name == engine else _OkEngine())

    payload = stdout.replace("PLACEHOLDER", str(target)).encode()

    async def fake_run(cmd, **kwargs):
        return (rc, payload, b"fake stderr")

    with patch(f"{module}.run_subprocess", side_effect=fake_run):
        return await detector.analyze_security_vulnerabilities([str(target)])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("engine", "case", "rc", "stdout", "expected", "n_findings"),
    CASES,
    ids=[f"{c[0]}-{c[1]}" for c in CASES],
)
async def test_engine_status_per_output_class(
    monkeypatch, tmp_path, engine, case, rc, stdout, expected, n_findings
):
    result = await _run_through_detector(monkeypatch, tmp_path, engine, rc, stdout)
    st = result.engine_status[engine]
    assert st["status"] == expected, (case, st)
    found = [m for ms in result.vulnerabilities_by_type.values() for m in ms if m.engine == engine]
    assert len(found) == n_findings, (case, found)
    others = {k: v["status"] for k, v in result.engine_status.items() if k != engine}
    assert set(others.values()) == {"ok"}, others
    if expected == "ok":
        assert st["reason"] is None
        assert result.scan_degraded is False
        assert result.degraded_reasons == []
    else:
        assert st["reason"], "a non-ok engine must say why"
        assert result.scan_degraded is True
        assert any(engine in r for r in result.degraded_reasons), result.degraded_reasons


# The validator's four exact probes (fake `bandit` on PATH through the detector).
VALIDATOR_BANDIT_PROBES = [
    ("exit 0 + garbage stdout", 0, "garbage!!", "failed"),
    ("exit 0 + empty stdout", 0, "", "failed"),
    (
        "exit 1 + errors[] + empty results",
        1,
        json.dumps({"errors": [{"filename": "a.py"}], "results": []}),
        "degraded",
    ),
    ("exit 2 + null", 2, "null", "failed"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "rc", "stdout", "expected"),
    VALIDATOR_BANDIT_PROBES,
    ids=[p[0] for p in VALIDATOR_BANDIT_PROBES],
)
async def test_validator_bandit_probes_are_never_ok(
    monkeypatch, tmp_path, case, rc, stdout, expected
):
    result = await _run_through_detector(monkeypatch, tmp_path, "bandit", rc, stdout)
    assert result.engine_status["bandit"]["status"] == expected
    assert any("bandit" in r for r in result.degraded_reasons)
    assert result.scan_degraded is True


# --------------------------------------------------------------------------
# The in-process pattern engine: never ok after a crash or a partial run
# --------------------------------------------------------------------------


def _detector_all_ok(monkeypatch, *, parse_ok=True):
    detector = SecurityScanService().detector

    async def _fake_parse(path):
        if not parse_ok and str(path).endswith("bad.py"):
            return None
        return ParseResult(
            success=True,
            file_path=str(path),
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
        )

    monkeypatch.setattr(detector, "_parse_file_for_security", _fake_parse)
    for attr in _ATTR.values():
        monkeypatch.setattr(detector, attr, _OkEngine())
    return detector


@pytest.mark.asyncio
async def test_pattern_engine_crash_is_failed_and_other_engines_still_run(monkeypatch, tmp_path):
    detector = _detector_all_ok(monkeypatch)

    async def _boom(_parsed, _low, _reasons=None):
        raise RuntimeError("bad regex")

    monkeypatch.setattr(detector, "_detect_vulnerabilities", _boom)
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    result = await detector.analyze_security_vulnerabilities([str(f)])
    assert result.engine_status["pattern"]["status"] == "failed"
    assert "bad regex" in result.engine_status["pattern"]["reason"]
    assert {result.engine_status[e]["status"] for e in _ATTR} == {"ok"}
    assert result.scan_degraded is True


@pytest.mark.asyncio
async def test_pattern_engine_unreadable_file_is_degraded(monkeypatch, tmp_path):
    detector = _detector_all_ok(monkeypatch)
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")

    def _unreadable(_path):
        raise PermissionError("denied")

    monkeypatch.setattr(detector.file_service, "read_file", _unreadable)
    result = await detector.analyze_security_vulnerabilities([str(f)])
    assert result.engine_status["pattern"]["status"] == "degraded"
    assert "could not be read" in result.engine_status["pattern"]["reason"]
    assert result.scan_degraded is True


@pytest.mark.asyncio
async def test_pattern_engine_unparsed_file_is_degraded(monkeypatch, tmp_path):
    detector = _detector_all_ok(monkeypatch, parse_ok=False)
    good = tmp_path / "a.py"
    good.write_text("x = 1\n")
    bad = tmp_path / "bad.py"
    bad.write_text("x = 1\n")
    result = await detector.analyze_security_vulnerabilities([str(good), str(bad)])
    assert result.engine_status["pattern"]["status"] == "degraded"
    assert "could not be parsed" in result.engine_status["pattern"]["reason"]
    assert result.scan_degraded is True


@pytest.mark.asyncio
async def test_pattern_engine_clean_run_is_ok(monkeypatch, tmp_path):
    detector = _detector_all_ok(monkeypatch)
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    result = await detector.analyze_security_vulnerabilities([str(f)])
    assert result.engine_status["pattern"] == {"status": "ok", "reason": None}
    assert result.scan_degraded is False
