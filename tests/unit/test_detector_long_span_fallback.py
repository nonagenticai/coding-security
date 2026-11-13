"""The bounded ({0,300}) detector rewrites must not lose main's long-span findings.

Validator repro on f29fe76: ``os.system('<400 chars>' + user)`` and
``cur.execute(f"SELECT <400 chars> WHERE id={user}")`` -- main found both,
HEAD reported 0 findings with ``scan_degraded=False``. Main's ORIGINAL pattern
now also runs (``regex`` module, per-call timeout, per-file budget) whenever
the content is longer than the bound; a check that does not finish degrades
the result instead of reporting it clean.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.security_config import SystemSecurityConfig
from models.security_models import SecurityLevel, SecurityValidationRequest
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService
from tests.cpu_budget import cpu_seconds_async

P = "a" * 400
# case -> (language, code, rule id main found). Each was lost on f29fe76.
LOST_ON_F29FE76 = {
    "os_system_plus_far": (
        "python",
        "os.system('" + P + "' + user)\n",
        "command_injection_python_1",
    ),
    "subproc_shell_far": (
        "python",
        "subprocess.run(cmd, x='" + P + "', shell=True)\n",
        "command_injection_python_1",
    ),
    "subproc_shell_plus_far": (
        "python",
        "subprocess.call('ls', shell=True, a='" + P + "' + u)\n",
        "command_injection_python_1",
    ),
    "sql_fstr_far": (
        "python",
        'cur.execute(f"SELECT ' + P + ' WHERE id={uid}")\n',
        "sql_injection_python_1",
    ),
    "sql_pct_far": (
        "python",
        'cur.execute("SELECT ' + P + ' WHERE id=%s" % uid)\n',
        "sql_injection_python_1",
    ),
    "render_far": (
        "python",
        'render_template_string("' + P + "\" + request.args['x'])\n",
        "xss_python_1",
    ),
    "innerhtml_far": (
        "javascript",
        "el.innerHTML = '" + P + "' + window.location.hash;\n",
        "xss_javascript_1",
    ),
    "innerhtml_plus_far": ("javascript", "el.innerHTML = '" + P + "' + x;\n", "xss_javascript_1"),
    "java_exec_far": (
        "java",
        'Runtime.getRuntime().exec("' + P + '" + cmd);\n',
        "command_injection_java_1",
    ),
    "java_pb_far": ("java", 'new ProcessBuilder("' + P + '" + cmd);\n', "command_injection_java_1"),
    "java_stmt_far": (
        "java",
        "Statement s = conn." + "x" * 400 + "createStatement();\n",
        "sql_injection_java_1",
    ),
    "traversal_far": (
        "python",
        "open(" + "x, " * 150 + "'../etc/passwd')\n",
        "path_traversal_generic_1",
    ),
    "ois_far": (
        "java",
        "ObjectInputStream in = new ObjectInputStream(" + P + "); in.readObject2;\n",
        "insecure_deserialization_java_1",
    ),
}
_SUFFIX = {"python": ".py", "javascript": ".js", "java": ".java"}


class _CleanEngine:
    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        return []


@pytest.fixture(scope="module")
def detector() -> SecurityVulnerabilityDetector:
    d = SecurityVulnerabilityDetector()
    for name in ("_bandit", "_secrets", "_semgrep", "_iac", "_image"):
        setattr(d, name, _CleanEngine())
    return d


def _service(detector) -> SystemSecurityService:
    return SystemSecurityService(SystemSecurityConfig(), None, detector=detector)


@pytest.mark.parametrize("case", sorted(LOST_ON_F29FE76))
async def test_scan_finds_long_span_case_again(case, detector, tmp_path: Path):
    lang, code, rule = LOST_ON_F29FE76[case]
    f = tmp_path / f"t{_SUFFIX[lang]}"
    f.write_text(code)
    result = await detector.analyze_security_vulnerabilities([str(f)])
    found = {m.pattern_id for ms in result.vulnerabilities_by_type.values() for m in ms}
    assert rule in found, (case, found, result.degraded_reasons)
    assert result.scan_degraded is False, result.degraded_reasons


_VALIDATE_LANGS = ("python", "javascript")  # /validate covers no other language


@pytest.mark.parametrize(
    "case", sorted(c for c, v in LOST_ON_F29FE76.items() if v[0] in _VALIDATE_LANGS)
)
async def test_validate_finds_long_span_case_again(case, detector):
    lang, code, rule = LOST_ON_F29FE76[case]
    svc = _service(detector)
    # The detector stage of /validate reports the rule itself...
    detector_violations, reasons = await svc._detect_vulnerabilities(code, lang)
    assert rule in {v.pattern_matched for v in detector_violations}, case
    assert reasons == []
    # ...and end to end the verdict equals that of the same line with the
    # padding shrunk inside the bound (where HEAD == main by construction).
    result = await svc.validate_code_security(
        SecurityValidationRequest(code=code, language=lang, security_level=SecurityLevel.MEDIUM)
    )
    short = await svc.validate_code_security(
        SecurityValidationRequest(
            code=code.replace(P, "a").replace("x" * 400, "x").replace("x, " * 150, "x, "),
            language=lang,
            security_level=SecurityLevel.MEDIUM,
        )
    )
    assert result.is_safe is short.is_safe, case
    assert {v.type for v in short.violations} <= {v.type for v in result.violations}, case
    assert result.analysis_degraded is False, result.degraded_reasons


@pytest.mark.parametrize(
    ("lang", "code", "rule"),
    [
        ("python", "os.system('" + P + "')\n", "command_injection_python_1"),
        (
            "python",
            'cur.execute("SELECT ' + P + ' WHERE id=%s", (uid,))\n',
            "sql_injection_python_1",
        ),
        ("javascript", "el.textContent = '" + P + "' + x;\n", "xss_javascript_1"),
        ("java", 'Runtime.getRuntime().exec("' + P + '");\n', "command_injection_java_1"),
    ],
)
async def test_long_span_negative_controls_stay_clean(lang, code, rule, detector):
    """Same long literals, no injected value: the fallback adds no finding."""
    reasons: list[str] = []
    matches = await detector.scan_inline(code, lang, reasons)
    assert rule not in {m.pattern_id for m in matches}
    assert reasons == []


# Catastrophic for main's unbounded `[^)]*\+.*\)` (quadratic on repeats of the
# anchor with no closing paren): the original cannot finish in budget.
ADVERSARIAL = "os.system(" * 20_000


async def test_scan_adversarial_long_line_is_degraded_never_clean(detector, tmp_path: Path):
    f = tmp_path / "adv.py"
    f.write_text(ADVERSARIAL)
    results = []

    async def scan() -> None:
        results.append(await detector.analyze_security_vulnerabilities([str(f)]))

    assert await cpu_seconds_async(scan, 2.0) < 2.0
    result = results[-1]
    assert result.scan_degraded is True
    reasons = " ".join(result.degraded_reasons)
    assert "adv.py:1:" in reasons and "command_injection_python_1" in reasons, reasons


async def test_validate_adversarial_long_line_is_degraded_never_safe(detector):
    # Every line under MAX_ANALYZED_LINE_CHARS (20k), so ONLY the fallback can
    # degrade it; main's `[^)]*` crosses newlines, so each anchor rescans the rest.
    code = ("os.system(" * 1_900 + "\n") * 10
    results = []

    async def validate() -> None:
        results.append(
            await _service(detector).validate_code_security(
                SecurityValidationRequest(code=code, language="python")
            )
        )

    assert await cpu_seconds_async(validate, 2.0) < 2.0
    result = results[-1]
    assert result.is_safe is False
    assert result.analysis_degraded is True
    assert any("command_injection_python_1" in r for r in result.degraded_reasons), (
        result.degraded_reasons
    )


async def test_fallback_timeout_is_recorded_not_swallowed(detector, monkeypatch):
    """With a zero budget every long-span check is reported, never skipped silently."""
    from services import security_detector as sd

    monkeypatch.setattr(sd, "_FALLBACK_FILE_BUDGET_S", 0.0)
    reasons: list[str] = []
    code = LOST_ON_F29FE76["os_system_plus_far"][1]
    await detector.scan_inline(code, "python", reasons)
    assert reasons and "per-file budget" in reasons[0], reasons
