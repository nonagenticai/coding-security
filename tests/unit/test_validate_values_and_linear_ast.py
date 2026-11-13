"""Dangerous callables taken as VALUES, namespace escapes, and a linear AST pass.

Rejected head 7f51d80 (measured by the validator against origin/main 0679e93):

* 5 (snippet, level) cells were UNSAFE on main and SAFE on the branch: it had
  lowered ``import os`` and flagged only CALLS of os.system, so a reference
  (``s, = (os.system,)``) or a namespace lookup (``os.__dict__['system']``)
  slid under the MEDIUM threshold. ``import os`` is HIGH again and every
  reference to a dangerous callable is CRITICAL in its own right.
* 9 further bypasses: the callable stored in a list/dict/class attribute,
  passed to partial()/map(), reached via ``from os import *``.
* ``_Resolver.string_builds`` was rescanned on every ``execute()``: quadratic
  (``"q='a'+b\\nc.execute(q)\\n" * n`` at 50k chars: 13 s).
"""

from __future__ import annotations

import ast

import pytest

from config.security_config import SystemSecurityConfig
from models.security_models import SecurityLevel, SecurityValidationRequest
from services import inline_rules
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService
from tests.cpu_budget import cpu_seconds_async

LEVELS = (SecurityLevel.LOW, SecurityLevel.MEDIUM, SecurityLevel.HIGH)

# The validator's 5 regressions: (snippet, levels main said UNSAFE).
REGRESSIONS = {
    "vars_os_dict": ("import os\nos.__dict__['system'](cmd)\n", ("medium", "high")),
    "star_os": ("from os import *\nsystem(cmd)\n", ("high",)),
    "tuple_unpack": ("import os\ns, = (os.system,)\ns(cmd)\n", ("medium", "high")),
}

# Must be UNSAFE at EVERY level (each is arbitrary command/code execution).
PY_ALWAYS_UNSAFE = {
    # the 3 regression snippets, now at every level
    **{k: v[0] for k, v in REGRESSIONS.items()},
    # the validator's 9 extra bypasses
    "os_dict_get": "import os\nos.__dict__.get('system')(cmd)\n",
    "list_alias": "import os\nfs = [os.system]\nfs[0](cmd)\n",
    "dict_alias": "import os\nd = {'r': os.system}\nd['r'](cmd)\n",
    "attr_on_obj": "import os\nclass A: r = os.system\nA.r(cmd)\n",
    "partial": "import os, functools\nf = functools.partial(os.system)\nf(cmd)\n",
    "map_system": "import os\nlist(map(os.system, cmds))\n",
    "os_execl_star": "from os import *\nexecl('/bin/sh','sh','-c',cmd)\n",
    "star_spawn": "from os import *\npopen(cmd)\n",
    "setattr_mod": "import os\nimport types\nm = types.SimpleNamespace(r=os.system)\nm.r(cmd)\n",
    # the rest of the reference / namespace-escape class
    "walrus_eval": "if (e := eval):\n    e(x)\n",
    "default_arg_eval": "def f(e=eval):\n    return e(x)\n",
    "subclasses": "().__class__.__bases__[0].__subclasses__()\n",
    "func_globals": "f.__globals__['os'].system(cmd)\n",
    "vars_os": "import os\nvars(os)['system'](cmd)\n",
    "getattr_nonliteral": "import os\nn = 'system'\ngetattr(os, n)(cmd)\n",
    "sys_modules_get": "import sys\nsys.modules.get('os').system(cmd)\n",
    "sys_modules_sub": "import sys\nsys.modules['subprocess'].run(cmd, shell=True)\n",
    "builtins_subscript": "__builtins__['eval'](x)\n",
    "pickle_ref": "import pickle\nloader = pickle.loads\nloader(blob)\n",
    "subprocess_ref": "import subprocess\nrunners = [subprocess.run]\nrunners[0](cmd, shell=True)\n",
    "pty_ref": "import pty\nf = pty.spawn\nf('/bin/sh')\n",
    "star_subprocess_bare": "from subprocess import *\ncheck_output(cmd, shell=True)\n",
}

JS_ALWAYS_UNSAFE = {
    "global_eval": "global['ev'+'al'](userInput);\n",
    "globalThis_eval": "globalThis['eval'](userInput);\n",
    "global_var": "const k = 'ev' + 'al';\nglobal[k](userInput);\n",
    "process_binding": "process.binding('spawn_sync').spawn(opts);\n",
    "process_dlopen": "process.dlopen(module, path);\n",
    "ctor_ctor": "[].constructor.constructor('return process')();\n",
}
# HIGH (blocking at MEDIUM and above).
JS_UNSAFE_FROM_MEDIUM = {
    "require_concat": "const cp = require('child_' + 'process');\ncp.exec(cmd);\n",
    "require_interp": "const cp = require(`child_${'process'}`);\ncp.exec(cmd);\n",
    "require_var": "const m = 'child_process';\nrequire(m).exec(cmd);\n",
}

# Clean code these rules must NOT flag (each is ordinary).
PY_CLEAN = {
    "getattr_sys_frozen": "import sys\nfrozen = getattr(sys, 'frozen', False)\n",
    "sys_modules_name": "import sys\nthis = sys.modules[__name__]\n",
    "re_compile_ref": "from re import compile\npat = compile('a+')\n",
    "model_eval_method": "model.eval()\nresult = model(x)\n",
    "path_join": "from os import path\np = path.join(a, b)\n",
}


class _CleanEngine:
    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        raise AssertionError("/validate must not run an external engine")


@pytest.fixture(scope="module")
def service() -> SystemSecurityService:
    d = SecurityVulnerabilityDetector()
    for name in ("_bandit", "_secrets", "_semgrep", "_iac", "_image"):
        setattr(d, name, _CleanEngine())
    return SystemSecurityService(SystemSecurityConfig(), None, detector=d)


async def _validate(service, code: str, language: str, level: SecurityLevel):
    return await service.validate_code_security(
        SecurityValidationRequest(code=code, language=language, security_level=level)
    )


@pytest.mark.parametrize("name", list(REGRESSIONS))
async def test_validator_regressions_unsafe_where_main_was(service, name):
    code, main_unsafe = REGRESSIONS[name]
    for level in main_unsafe:
        r = await _validate(service, code, "python", SecurityLevel(level))
        assert r.is_safe is False, (name, level)


@pytest.mark.parametrize("name", list(PY_ALWAYS_UNSAFE))
@pytest.mark.parametrize("level", LEVELS)
async def test_python_reference_bypasses_unsafe_at_every_level(service, name, level):
    r = await _validate(service, PY_ALWAYS_UNSAFE[name], "python", level)
    assert r.is_safe is False
    assert any(v.severity == SecurityLevel.CRITICAL for v in r.violations)


@pytest.mark.parametrize("name", list(JS_ALWAYS_UNSAFE))
@pytest.mark.parametrize("level", LEVELS)
async def test_js_global_and_binding_unsafe_at_every_level(service, name, level):
    r = await _validate(service, JS_ALWAYS_UNSAFE[name], "javascript", level)
    assert r.is_safe is False


@pytest.mark.parametrize("name", list(JS_UNSAFE_FROM_MEDIUM))
@pytest.mark.parametrize("level", (SecurityLevel.MEDIUM, SecurityLevel.HIGH))
async def test_js_computed_require_unsafe_from_medium(service, name, level):
    r = await _validate(service, JS_UNSAFE_FROM_MEDIUM[name], "javascript", level)
    assert r.is_safe is False


@pytest.mark.parametrize("name", list(PY_CLEAN))
def test_reference_rules_do_not_flag_ordinary_code(name):
    found = inline_rules.analyze_python_calls(ast.parse(PY_CLEAN[name]))
    assert [v for v in found if v.severity == SecurityLevel.CRITICAL] == []


def test_import_os_is_high_again(service):
    """Restored to main's severity in both places that grade it."""
    rules = {r["pattern"]: r["severity"] for r in service.dangerous_patterns["python"]}
    assert rules[r"import\s+os\b"] == "high"


async def test_import_os_ast_severity_is_high(service):
    found = await service._validate_python_imports(ast.parse("import os").body[0])
    assert found[0].severity == SecurityLevel.HIGH


def test_ast_budget_degrades_never_safe_and_control():
    tree = ast.parse("f(a)\n" * 50)
    over = inline_rules.analyze_python_calls(tree, max_nodes=100)
    assert [v.pattern_matched for v in over] == [inline_rules.AST_BUDGET_PATTERN]
    under = inline_rules.analyze_python_calls(tree, max_nodes=10_000)
    assert under == []


async def test_ast_budget_makes_validate_degraded(service):
    code = "f(a)\n" * 39_000  # 156k non-context nodes > MAX_AST_NODES
    r = await _validate(service, code, "python", SecurityLevel.LOW)
    assert r.analysis_degraded is True
    assert r.is_safe is False
    assert any("budget" in reason for reason in r.degraded_reasons)


def _fill(unit: str, n: int = 199_900) -> str:
    return unit * (n // len(unit))


TIMED = {
    # the two quadratic inputs (13 s / 4.25 s at 50k chars on 7f51d80)
    "build_exec_pairs": _fill("q='a'+b\nc.execute(q)\n"),
    "augassign_pairs": "q=''\n" + _fill("q+=b\nc.execute(q)\n"),
    # the same with real SQL (findings on every line, still linear)
    "build_exec_pairs_sql": _fill("q='select '+b\nc.execute(q)\n"),
    "builds_then_execs": _fill("q='select '+b\n", 99_990) + _fill("c.execute(q)\n", 99_990),
    "alias_chain": _fill("a=b\nb=a\n"),
    "assign_chain": _fill("a=a.b\n"),
    "deep_attr": "x" + ".a" * 99_990 + "\n",
    "many_getattr": "import os\n" + _fill("getattr(os, n)\n"),
    "many_refs": "import os\n" + _fill("x = [os.system]\n"),
    "star_many": "from os import *\n" + _fill("system(c)\n"),
    "name_then_spaces": "rbuRBU" + " " * 199_000,
}


@pytest.mark.parametrize("name", list(TIMED))
async def test_validate_is_linear_on_200k_inputs(service, name):
    code = TIMED[name]
    assert len(code) <= 200_000
    assert (
        await cpu_seconds_async(
            lambda: _validate(service, code, "python", SecurityLevel.MEDIUM), 2.0
        )
        < 2.0
    )
