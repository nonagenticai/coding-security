"""Regression: one POST /api/security/validate could stall the service.

Measured 2026-10-12 on the branch that wired the vulnerability detector into
/validate: the widened hardcoded-secret regex
``(?:secret|passw(?:or)?d|...)\\w*\\s*[:=]...`` is quadratic on a line of the
keyword repeated — ``"secret" * 33334`` (200 KB) took 40-52 s, on the event
loop, and ``SecurityValidationRequest.code`` had no size limit. An audit of
every regex /validate now runs found the same shape (``X.*Y`` restarting at
each ``X``) in ~25 detector patterns and metadata counters.

Every timing below is on an adversarial 200 KB input and must finish well under
the 0.5 s budget; on the pre-fix code the keyword inputs take tens of seconds.

The linearity budgets are measured in CPU time (tests/cpu_budget.py, #118).
"""

from __future__ import annotations

import asyncio
import re
import time

import pytest
from pydantic import ValidationError

from config.security_config import SystemSecurityConfig
from models.security_models import (
    SecurityLevel,
    SecurityValidationRequest,
    SupportedLanguage,
)
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService
from tests.cpu_budget import is_linear, is_linear_async

N = 200_000
BUDGET_S = 0.5
# The contract (models.security_models.MAX_VALIDATE_CODE_CHARS /
# MAX_ANALYZED_LINE_CHARS), spelled out so the test also runs against code
# that predates the constants.
MAX_VALIDATE_CODE_CHARS = 200_000
MAX_ANALYZED_LINE_CHARS = 20_000


def _rep(unit: str) -> str:
    return (unit * (N // len(unit) + 1))[:N]


ADVERSARIAL = {
    "secret": _rep("secret"),
    "password": _rep("password"),
    "api_key": _rep("api_key"),
    "_secret": _rep("_secret"),
    "auth_token": _rep("auth_token"),
    "secret=": _rep("secret="),
    "equals": _rep("="),
    "dquote": _rep('"'),
    "squote": _rep("'"),
    "word": _rep("a"),
    "space": _rep(" "),
    "newline": _rep("\n"),
    "paren": _rep("("),
    "plus_quote": _rep('"+'),
    "execute": _rep('.executeQuery("'),
    "open": _rep("open("),
    "os_system": _rep("os.system("),
    "statement": _rep("Statement"),
    "dircontext": _rep("DirContext"),
    "readfile": _rep("readFile"),
    "render": _rep("render_template_string("),
    "import": _rep("import "),
    "innerhtml": _rep(".innerHTML = "),
    "processbuilder": _rep("ProcessBuilder("),
    "secret_open_quote": 'secret = "' + "a" * (N - 10),
    "fstring_braces": '.execute(f"' + "{" * (N - 11),
    "percent_s": '.execute("' + "%s" * ((N - 10) // 2),
    "subprocess_call": _rep("subprocess.call("),
    "shell_true": "subprocess.run(x, " + "shell=True" * ((N - 18) // 10),
    "token": _rep("token"),
    "_token": _rep("_token"),
    "dotted": _rep("a."),
    "xoxb": _rep("xoxb-"),
    "pem": _rep("-----BEGIN "),
    "ghp": _rep("ghp_"),
    "github_pat": _rep("github_pat_"),
    "child_process": _rep("child_process "),
    "require": _rep("require("),
    "query_tpl": _rep(".query(`"),
    "query_sq": _rep(".query('"),
    "q_name": _rep('"api_key": "'),
    "typed_name": _rep("api_key: str = '"),
    # Two adjacent plain [ \t]* runs in _ASSIGN_LITERAL: ~200 s at 200k.
    "name_then_spaces": "rbuRBU" + " " * (N - 6),
    "os_system_newlines": _rep("os.system(\n"),
    "os_system_pluses": _rep("os.system(" + "+" * 290),
    "execute_query_newlines": _rep(".executeQuery('\n"),
    "fstring_empty_braces": '.execute(f"' + "{}" * ((N - 11) // 2),
    "global_bracket": _rep("globalThis["),
    "require_concat": _rep("require('a' +"),
    "getattr_literal": _rep("getattr(os, 'x"),
}


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


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_every_detector_and_table_regex_is_linear(name, detector):
    """Each regex /validate runs, on each adversarial input, under budget."""
    data = ADVERSARIAL[name]
    slow = []
    regexes = [
        (cp, re.IGNORECASE | re.MULTILINE) for p in detector.patterns for cp in p.code_patterns
    ]
    for rules in _service(detector).dangerous_patterns.values():
        regexes.extend((r["pattern"], re.IGNORECASE) for r in rules)
    from services import inline_rules

    regexes.extend(
        (rx.pattern, rx.flags)
        for rx in (
            inline_rules._ASSIGN_LITERAL,
            inline_rules._SECRET_NAME,
            inline_rules._SQL_KEYWORD,
        )
    )
    for pattern, flags in regexes:
        rx = re.compile(pattern, flags)
        ok, detail = is_linear(lambda d, rx=rx: sum(1 for _ in rx.finditer(d)), data, BUDGET_S)
        if not ok:
            slow.append((detail, pattern))
    assert slow == []


@pytest.mark.parametrize("name", list(ADVERSARIAL))
async def test_metadata_counters_are_linear(name, detector):
    """The per-language metadata counters (findall over the whole file) too."""
    data = ADVERSARIAL[name]
    for fn in (
        detector._analyze_python_security_patterns,
        detector._analyze_js_security_patterns,
        detector._analyze_java_security_patterns,
    ):
        ok, detail = await is_linear_async(fn, data, BUDGET_S)
        assert ok, f"{fn.__name__}: {detail}"
    ok, detail = await is_linear_async(
        lambda d: detector._analyze_code_patterns(d, "go"), data, BUDGET_S
    )
    assert ok, f"_analyze_code_patterns(go): {detail}"


@pytest.mark.parametrize("language", [SupportedLanguage.PYTHON, SupportedLanguage.JAVASCRIPT])
@pytest.mark.parametrize("name", ["secret", "password", "_secret", "dquote", "execute", "open"])
async def test_validate_end_to_end_is_fast_and_never_blocks_the_loop(name, language, detector):
    """The whole /validate analysis, while a ticker on the serving loop keeps
    running: the work happens off the event loop."""
    gaps: list[float] = []
    stop = asyncio.Event()

    async def ticker() -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    tick = asyncio.create_task(ticker())
    await asyncio.sleep(0.02)
    t0 = time.perf_counter()
    result = await _service(detector).validate_code_security(
        SecurityValidationRequest(
            code=ADVERSARIAL[name], language=language, security_level=SecurityLevel.MEDIUM
        )
    )
    elapsed = time.perf_counter() - t0
    stop.set()
    await tick

    assert elapsed < 3.0
    # A multi-second loop stall is the regression this guards (the pre-fix code
    # blocked for 40-52 s), and `elapsed` above is what actually catches it: the
    # work here finishes in ~0.04 s, so an on-loop run shows a gap of the same
    # order — well under any bound that survives a shared runner. Measured
    # 2026-11-04: max gap ~0.02 s locally, 0.40 s on the CI node while a
    # co-tenant job ran (this bound failed there and passed on re-run). The
    # bound is therefore set to tolerate runner scheduling noise; it still
    # fails on a stall approaching the 3 s work budget.
    assert max(gaps) < 1.0, f"event loop blocked for {max(gaps):.2f}s"
    # A single 200 KB line is past the analysed-line bound: never "safe".
    assert result.analysis_degraded is True
    assert result.is_safe is False


def test_validate_request_code_is_bounded():
    SecurityValidationRequest(code="x" * MAX_VALIDATE_CODE_CHARS, language="python")
    with pytest.raises(ValidationError):
        SecurityValidationRequest(code="x" * (MAX_VALIDATE_CODE_CHARS + 1), language="python")


def test_validate_endpoint_rejects_oversized_code_with_422(test_client, tenant_headers):
    response = test_client.post(
        "/api/security/validate",
        json={"code": "x" * (MAX_VALIDATE_CODE_CHARS + 1), "language": "python"},
        headers=tenant_headers,
    )
    assert response.status_code == 422


async def test_long_line_is_degraded_not_safe(detector):
    """Planted: a harmless but over-long line. Control: the same content wrapped."""
    long_line = "x = " + "1 + " * (MAX_ANALYZED_LINE_CHARS // 4) + "1\n"
    result = await _service(detector).validate_code_security(
        SecurityValidationRequest(code=long_line, language="python")
    )
    assert result.analysis_degraded is True
    assert result.is_safe is False
    assert any("chars" in r for r in result.degraded_reasons)

    wrapped = "".join(f"x{i} = 1\n" for i in range(500))
    control = await _service(detector).validate_code_security(
        SecurityValidationRequest(code=wrapped, language="python")
    )
    assert control.analysis_degraded is False
    assert control.is_safe is True


async def test_parser_overflow_is_not_a_500_and_not_safe(detector):
    """15,000 chained unary minus overflow CPython's parser (MemoryError, not
    SyntaxError); it escaped validate_code_security as an unhandled exception.
    The line stays under the long-line bound so only the parser path is tested."""
    code = "x = " + "-" * 15_000 + "1\n"
    assert len(code) < MAX_ANALYZED_LINE_CHARS
    result = await _service(detector).validate_code_security(
        SecurityValidationRequest(code=code, language="python")
    )
    assert result.is_safe is False


def test_contract_constants_match_the_model():
    from models import security_models

    assert security_models.MAX_VALIDATE_CODE_CHARS == MAX_VALIDATE_CODE_CHARS
    assert security_models.MAX_ANALYZED_LINE_CHARS == MAX_ANALYZED_LINE_CHARS
