"""No rule may be weaker than on origin/main (0679e93).

``tests/fixtures/main_rule_snapshot_0679e93.json`` is a FROZEN snapshot of
main's rule tables (generated once from ``git show 0679e93:src/...``; main is
never imported here). For every main rule this asserts that HEAD has the same
rule with a severity >= main's, or a documented replacement that covers it.

Documented replacements: the detector's unbounded ``.*`` / ``[^)]*`` spans were
rewritten as bounded/atomic spans (``{0,300}``) because the unbounded forms were
quadratic (ReDoS) on adversarial input. Within a 300-char span they match
exactly what main matched -- asserted below by a seeded differential fuzz.
Beyond 300 chars they do not on their own, so main's ORIGINAL pattern also
runs (``security_detector._UNBOUNDED_ORIGINALS``, ``regex`` with a timeout and
a per-file budget; a check that does not finish degrades the result) --
asserted below on lines of 300-20k chars.
"""

from __future__ import annotations

import ast
import json
import random
import re
from pathlib import Path

import pytest

from config.security_config import SystemSecurityConfig
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService

SNAPSHOT = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "main_rule_snapshot_0679e93.json").read_text()
)
_RANK = {None: 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# main code_pattern index -> HEAD's bounded rewrite at the same index. Each key
# is (pattern id, index); the anchors seed the differential fuzz.
BOUNDED_REWRITES: dict[tuple[str, int], list[str]] = {
    ("command_injection_java_1", 0): ["Runtime.getRuntime().exec("],
    ("command_injection_java_1", 1): ["ProcessBuilder("],
    ("command_injection_python_1", 0): ["os.system("],
    ("command_injection_python_1", 1): ["subprocess.call(", "shell=True"],
    ("command_injection_python_1", 2): ["subprocess.run(", "shell=True"],
    ("command_injection_python_1", 3): ["subprocess.run(", "subprocess.Popen(", "shell=True"],
    ("insecure_deserialization_java_1", 1): ["ObjectInputStream", "read"],
    ("insecure_deserialization_java_1", 2): ["XMLDecoder", "read"],
    ("ldap_injection_generic_1", 0): ["LdapName", "new", "DirContext", "search"],
    ("ldap_injection_generic_1", 1): ["FilterEncoder", "LdapContext", "search"],
    ("log4shell_cve_2021_44228_1", 1): ["log4j", "2.0-16", "2.16.1"],
    ("log4shell_cve_2021_44228_1", 2): ["LoggerFactory.getLogger(", ").info(", ").debug("],
    ("path_traversal_generic_1", 0): ["open(", "'../", '"..\\'],
    ("path_traversal_generic_1", 1): ["File(", "'../", '"../'],
    ("path_traversal_generic_1", 2): ["readFile", "template"],
    ("spring4shell_cve_2022_22965_1", 1): ["WebDataBinder", "bindingResult"],
    ("spring4shell_cve_2022_22965_1", 3): ["@Controller", "@RestController", "@RequestMapping"],
    ("sql_injection_java_1", 0): ["Statement", "createStatement()"],
    ("sql_injection_java_1", 1): ['.executeQuery("', ".executeQuery('"],
    ("sql_injection_python_1", 2): ['.execute(f"', ".execute(f'", "{uid}"],
    ("sql_injection_python_1", 4): ['.execute("', ".execute('", "%s", "%d"],
    ("xml_injection_generic_1", 1): ["setFeature", "XMLConstants.ACCESS_EXTERNAL"],
    ("xml_injection_generic_1", 2): ["XXE", "DOCTYPE", "ENTITY"],
    ("xss_javascript_1", 0): [".innerHTML = ", "location", "document.URL"],
    ("xss_javascript_1", 1): [".innerHTML = "],
    ("xss_python_1", 0): ["render_template_string(", "request."],
    ("xss_python_1", 1): ["Template(", ").render(", "request."],
}
_FUZZ_TOKENS = [*"()\"'+{}%=;. \\/[]", "\n", "x", "uid", "True", "s", "d", "..", "a b"]


def _head_snapshot() -> dict:
    svc = SystemSecurityService(SystemSecurityConfig())
    return {
        "dangerous_patterns": {
            lang: {r["pattern"]: r["severity"] for r in rules}
            for lang, rules in svc.dangerous_patterns.items()
        },
        "detector": {p.id: p for p in SecurityVulnerabilityDetector().patterns},
        "svc": svc,
    }


@pytest.fixture(scope="module")
def head():
    return _head_snapshot()


def test_snapshot_is_main_and_has_every_table():
    assert SNAPSHOT["source"].startswith("git show 0679e93")
    assert SNAPSHOT["dangerous_patterns"]["python"]
    assert SNAPSHOT["dangerous_patterns"]["javascript"]
    assert SNAPSHOT["ast_import_severity"]["import os"] == "high"
    assert len(SNAPSHOT["detector_patterns"]) >= 10


@pytest.mark.parametrize("lang", ["python", "javascript"])
def test_every_main_dangerous_pattern_is_on_head_at_least_as_severe(head, lang):
    weaker = []
    for rule in SNAPSHOT["dangerous_patterns"][lang]:
        sev = head["dangerous_patterns"][lang].get(rule["pattern"])
        if _RANK[sev] < _RANK[rule["severity"]]:
            weaker.append((rule["pattern"], rule["severity"], sev))
    assert weaker == []


async def test_ast_import_and_call_severities_not_weaker(head):
    svc = head["svc"]
    for stmt, main_sev in SNAPSHOT["ast_import_severity"].items():
        code = stmt if stmt.startswith("import ") else f"{stmt} x"
        found = await svc._validate_python_imports(ast.parse(code).body[0])
        assert found, stmt
        assert _RANK[found[0].severity.value] >= _RANK[main_sev], stmt
    for fn, main_sev in SNAPSHOT["ast_call_severity"].items():
        found = await svc._validate_python_ast(f"{fn}(x)\n")
        sev = max((_RANK[v.severity.value] for v in found), default=0)
        assert sev >= _RANK[main_sev], fn


async def test_js_global_and_import_severities_not_weaker(head):
    svc = head["svc"]
    for code, main_sev in SNAPSHOT["js_global_access_severity"].items():
        found = await svc._validate_javascript_patterns(code)
        assert found and _RANK[found[0].severity.value] >= _RANK[main_sev], code
    for code, main_sev in SNAPSHOT["js_import_severity"].items():
        found = await svc._analyze_javascript_imports(code)
        got = found[0].severity.value if found else None
        assert _RANK[got] >= _RANK[main_sev], code


def test_detector_patterns_same_or_documented_bounded_rewrite(head):
    for pid, main in SNAPSHOT["detector_patterns"].items():
        hp = head["detector"].get(pid)
        assert hp is not None, f"{pid} removed"
        assert _RANK[hp.severity.value] >= _RANK[main["severity"]], pid
        assert len(hp.code_patterns) >= len(main["code_patterns"]), pid
        for i, cp in enumerate(main["code_patterns"]):
            if cp in hp.code_patterns:
                continue
            assert (pid, i) in BOUNDED_REWRITES, f"{pid}[{i}] changed without a documented rewrite"


@pytest.mark.parametrize(("pid", "idx"), sorted(BOUNDED_REWRITES))
def test_bounded_rewrite_matches_everything_main_matched_within_300_chars(head, pid, idx):
    """Seeded differential fuzz: every string main's regex matched, HEAD's does."""
    main_re = re.compile(SNAPSHOT["detector_patterns"][pid]["code_patterns"][idx], re.I | re.M)
    head_re = re.compile(head["detector"][pid].code_patterns[idx], re.I | re.M)
    anchors = BOUNDED_REWRITES[(pid, idx)]
    rng = random.Random(f"{pid}:{idx}")
    positives = 0
    for _ in range(4000):
        parts = [rng.choice(anchors)]
        for _ in range(rng.randint(1, 18)):
            parts.append(rng.choice(_FUZZ_TOKENS + anchors))
        s = "".join(parts)
        if main_re.search(s):
            positives += 1
            assert head_re.search(s), repr(s)
    assert positives > 0, "fuzz never produced a main match: the check is vacuous"


# One main-matching line per rewrite, as pieces; padding of 300-20k chars is
# inserted into random gaps, so main's match spans far beyond the bound.
LONG_SKELETONS: dict[tuple[str, int], list[str]] = {
    ("command_injection_java_1", 0): ["Runtime.getRuntime().exec(", '"', '" + cmd', ")"],
    ("command_injection_java_1", 1): ["ProcessBuilder(", '"', '" + cmd', ")"],
    ("command_injection_python_1", 0): ["os.system(", "'", "' + user", ")"],
    ("command_injection_python_1", 1): ["subprocess.call(", "'ls', ", "shell=True, ", "a + u", ")"],
    ("command_injection_python_1", 2): ["subprocess.run(", "x, ", "shell=True, ", "a + u", ")"],
    ("command_injection_python_1", 3): ["subprocess.run(", "cmd, ", "x, ", "shell=True)"],
    ("insecure_deserialization_java_1", 1): ["ObjectInputStream", " in ", ".read"],
    ("insecure_deserialization_java_1", 2): ["XMLDecoder", " d ", ".read"],
    ("ldap_injection_generic_1", 0): ["LdapName", " ", "new", " ", "+"],
    ("ldap_injection_generic_1", 1): ["LdapContext", " ", "search"],
    ("log4shell_cve_2021_44228_1", 1): ["log4j", " ", "2.16.1"],
    ("log4shell_cve_2021_44228_1", 2): ["LoggerFactory.getLogger(", "x", ").info("],
    ("path_traversal_generic_1", 0): ["open(", "x, ", "'../etc"],
    ("path_traversal_generic_1", 1): ["File(", "x, ", '"../etc'],
    ("path_traversal_generic_1", 2): ["readFile", " ", "+"],
    ("spring4shell_cve_2022_22965_1", 1): ["WebDataBinder", " ", "bindingResult"],
    ("spring4shell_cve_2022_22965_1", 3): ["@RestController", " ", "@RequestMapping"],
    ("sql_injection_java_1", 0): ["Statement", " s = conn.", "createStatement()"],
    ("sql_injection_java_1", 1): ['.executeQuery("', "SELECT ", "+ id", '"'],
    ("sql_injection_python_1", 2): ['.execute(f"', "SELECT ", "{uid}", " x", '"'],
    ("sql_injection_python_1", 4): ['.execute("', "SELECT ", "%s", " x", '" % uid'],
    ("xml_injection_generic_1", 1): ["setFeature", " ", "XMLConstants.ACCESS_EXTERNAL"],
    ("xml_injection_generic_1", 2): ["DOCTYPE", " ", "ENTITY"],
    ("xss_javascript_1", 0): [".innerHTML = ", "'x' + ", "window.location.hash"],
    ("xss_javascript_1", 1): [".innerHTML = ", "'x'", " + ", "y"],
    ("xss_python_1", 0): ["render_template_string(", '"x" + ', "request.args"],
    ("xss_python_1", 1): ["Template(", "s", ").render(", "x=", "request.x"],
}


def test_every_bounded_rewrite_has_a_long_skeleton():
    assert set(LONG_SKELETONS) == set(BOUNDED_REWRITES)


def test_every_bounded_rewrite_keeps_mains_original_as_fallback(head):
    from services.security_detector import _UNBOUNDED_ORIGINALS

    for pid, idx in BOUNDED_REWRITES:
        bounded = head["detector"][pid].code_patterns[idx]
        main = SNAPSHOT["detector_patterns"][pid]["code_patterns"][idx]
        assert _UNBOUNDED_ORIGINALS.get(bounded) == main, (pid, idx)


@pytest.mark.parametrize(("pid", "idx"), sorted(BOUNDED_REWRITES))
async def test_head_finds_everything_main_found_on_300_to_20k_char_lines(head, pid, idx):
    """Seeded differential beyond the bound: on lines of 300-20k chars that
    main's regex matched, HEAD reports the same rule (bounded rewrite +
    main-equivalent fallback) and no check was skipped."""
    from services.security_detector import ParseResult, ParserType, _FallbackBudget

    main_re = re.compile(SNAPSHOT["detector_patterns"][pid]["code_patterns"][idx], re.I | re.M)
    pattern = head["detector"][pid]
    detector = SecurityVulnerabilityDetector()
    lang = "python" if pattern.language == "any" else pattern.language
    pieces = LONG_SKELETONS[(pid, idx)]
    rng = random.Random(f"long:{pid}:{idx}")
    long_positives = 0
    for _ in range(25):
        gaps = rng.sample(range(1, len(pieces)), rng.randint(1, len(pieces) - 1))
        budget_chars = rng.randint(300, 19_500)
        out = []
        for i, piece in enumerate(pieces):
            if i in gaps:
                out.append("a" * (budget_chars // len(gaps)))
            out.append(piece)
        line = "".join(out)
        assert 300 < len(line) < 20_000
        m = main_re.search(line)
        assert m, (pid, idx, "skeleton no longer matches main")
        long_positives += len(m.group()) > 300
        budget = _FallbackBudget.for_file("x")
        parsed = ParseResult(
            success=True, file_path="x", language=lang, parser_used=ParserType.REGEX_FALLBACK
        )
        content = "x = 1\n" + line + "\ny = 2\n"
        found = await detector._apply_security_pattern(
            pattern, parsed, content, content.split("\n"), budget
        )
        assert any(f.line_start == 2 for f in found), (pid, idx, len(line))
        assert budget.reasons == []
    assert long_positives > 0, "corpus never exercised a >300-char match"
