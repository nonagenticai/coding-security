"""/api/security/validate is a FAST INLINE GATE: in-process rules only.

Measured 2026-10-12 on 156aa40: /validate ran the external engines
(detect-secrets, bandit, semgrep, trivy) on the inline snippet. detect-secrets
alone took >300 s on ``("secret" * 33334)[:199999]``, a real call held a worker
for 150 s, and an absent semgrep degraded every /validate. The same review found
snippets that were unsafe on main and SAFE on 156aa40, because the line table
cannot follow import aliases (``import os as o; o.execvp(...)``).

Every planted defect below has a clean control.
"""

from __future__ import annotations

import pytest

from config.security_config import SystemSecurityConfig
from models.security_models import SecurityLevel, SecurityValidationRequest
from services.bandit_scanner import BanditScanner
from services.iac_scanner import IaCScanner
from services.secrets_scanner import SecretsScanner
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService
from services.semgrep_scanner import SemgrepScanner
from tests.cpu_budget import is_linear


class _ExplodingEngine:
    """An engine that must never be reached from /validate."""

    def __init__(self) -> None:
        self.calls = 0

    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        self.calls += 1
        raise AssertionError("/validate invoked an external engine")


@pytest.fixture
def engines():
    return {n: _ExplodingEngine() for n in ("_bandit", "_secrets", "_semgrep", "_iac", "_image")}


@pytest.fixture
def service(engines) -> SystemSecurityService:
    d = SecurityVulnerabilityDetector()
    for name, eng in engines.items():
        setattr(d, name, eng)
    return SystemSecurityService(SystemSecurityConfig(), None, detector=d)


async def _validate(svc, code, language="python", level=SecurityLevel.MEDIUM):
    return await svc.validate_code_security(
        SecurityValidationRequest(code=code, language=language, security_level=level)
    )


# --- no external engine, ever -------------------------------------------------


async def test_validate_never_invokes_an_external_engine(service, engines):
    sqli = 'cur.execute("SELECT * FROM t WHERE id=" + uid)\n'
    result = await _validate(service, sqli)
    assert result.is_safe is False
    assert any(v.type == "sql_injection" for v in result.violations)
    assert result.analysis_degraded is False
    assert sum(e.calls for e in engines.values()) == 0


async def test_absent_engines_do_not_degrade_validate(service):
    for name in ("_bandit", "_secrets", "_semgrep", "_iac", "_image"):
        getattr(service._detector, name).is_available = lambda: False
    result = await _validate(service, "def f(x):\n    return x + 1\n")
    assert result.is_safe is True
    assert result.analysis_degraded is False
    assert result.degraded_reasons == []


# --- AST: import aliases resolved, dangerous CALLS flagged --------------------

PY_UNSAFE = {
    "o.execvp": "import os as o\no.execvp('sh', ['sh', '-c', cmd])\n",
    "o.system": "import os as o\no.system(cmd)\n",
    "o.system-literal": "import os as o\no.system('ls')\n",
    "from-os-system": "from os import system\nsystem(cmd)\n",
    "from-os-system-as": "from os import system as run\nrun(cmd)\n",
    "from-os-popen": "from os import popen\npopen(cmd).read()\n",
    "o.spawnl": "import os as o\no.spawnl(o.P_WAIT, '/bin/sh', 'sh')\n",
    "reverse-shell": (
        "import socket,os\ns=socket.socket()\ns.connect((h,p))\nos.dup2(s.fileno(),0)\n"
    ),
    "reverse-shell-alias": (
        "import socket as so, os as o\ns=so.socket()\ns.connect((h,p))\no.dup2(s.fileno(),1)\n"
    ),
    "Popen-as-P-shell": "from subprocess import Popen as P\nP(cmd, shell=True)\n",
    "Popen-as-P-var": "from subprocess import Popen as P\nP(cmd)\n",
    "sp.run-var": "import subprocess as sp\nsp.run(cmd)\n",
    "getoutput": "from subprocess import getoutput\ngetoutput(cmd)\n",
    "pty.spawn": "import pty\npty.spawn('/bin/sh')\n",
    "eval-alias": "e = eval\ne(x)\n",
    "builtins-exec": "import builtins as b\nb.exec(src)\n",
    "from-builtins-eval": "from builtins import eval as ev\nev(x)\n",
    "import_module-var": "import importlib as il\nm = il.import_module(name)\n",
    "__import__-var": "m = __import__(name)\n",
    "import_module-os-system": 'import importlib\nimportlib.import_module("os").system(cmd)\n',
    "getattr-alias-os": "import os as o\nf = getattr(o, name)\nf(cmd)\n",
    "pickle-from": "from pickle import loads\nobj = loads(blob)\n",
    "pickle-alias": "import pickle as pk\nobj = pk.loads(blob)\n",
    "marshal": "import marshal\ncode = marshal.loads(blob)\n",
    "yaml.load": "import yaml\ncfg = yaml.load(text)\n",
    "yaml.FullLoader": "import yaml\ncfg = yaml.load(text, Loader=yaml.FullLoader)\n",
    "shelve": "import shelve\ndb = shelve.open(path)\n",
    "ctypes-from": "from ctypes import CDLL\nlib = CDLL(path)\n",
    "rmtree-alias": "from shutil import rmtree\nrmtree(user_path)\n",
    "sql-fstring": "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
    "sql-percent": "cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n",
    "sql-format": "cur.execute(\"SELECT * FROM users WHERE name = '{}'\".format(name))\n",
    "sql-executemany": 'cur.executemany(f"INSERT INTO t VALUES ({v})", rows)\n',
    "sql-raw": "User.objects.raw(\"SELECT * FROM u WHERE n='{}'\".format(n))\n",
    "sql-var": 'q = f"DELETE FROM t WHERE id={uid}"\ncursor.execute(q)\n',
    "sql-concat-var": 'q = "SELECT * FROM t WHERE id=" + uid\ncur.execute(q)\n',
}


@pytest.mark.parametrize("name", list(PY_UNSAFE))
@pytest.mark.parametrize("level", [SecurityLevel.MEDIUM, SecurityLevel.HIGH])
async def test_python_dangerous_calls_are_unsafe(service, name, level):
    result = await _validate(service, PY_UNSAFE[name], level=level)
    assert result.is_safe is False, (name, result.violations)


@pytest.mark.parametrize("name", ["o.execvp", "from-os-system-as", "reverse-shell"])
async def test_critical_aliased_exec_is_unsafe_even_at_low(service, name):
    result = await _validate(service, PY_UNSAFE[name], level=SecurityLevel.LOW)
    assert result.is_safe is False
    assert any(v.severity == SecurityLevel.CRITICAL for v in result.violations)


@pytest.mark.parametrize("name", [k for k in PY_UNSAFE if k.startswith("sql-")])
async def test_built_sql_is_unsafe_at_every_level(service, name):
    for level in SecurityLevel:
        result = await _validate(service, PY_UNSAFE[name], level=level)
        assert result.is_safe is False, (name, level)


PY_CLEAN = {
    "param-sql": "def get(cur, uid):\n    cur.execute('SELECT * FROM t WHERE id = %s', (uid,))\n",
    "literal-sql": "cur.execute('SELECT 1')\n",
    "yaml.safe_load": "import yaml\ncfg = yaml.safe_load(text)\n",
    "yaml.SafeLoader": "import yaml\ncfg = yaml.load(text, Loader=yaml.SafeLoader)\n",
    "socket-no-dup2": "import socket\ns = socket.create_connection((h, 80))\n",
    # (`import os` itself is HIGH, as on main, so the alias control uses a
    # from-import: resolving `pj` to os.path.join must not flag it.)
    "os.path": "from os import path as pj\np = pj.join(a, b)\n",
    "low-entropy-key": 'cache_key = "user_profile_settings"\n',
    "logging-percent": "import logging\nlogging.info('x=%s' % x)\n",
}


@pytest.mark.parametrize("name", list(PY_CLEAN))
async def test_python_clean_controls_stay_safe(service, name):
    result = await _validate(service, PY_CLEAN[name])
    assert result.is_safe is True, (name, result.violations)


# --- secrets (in-process shapes + generic entropy) ---------------------------

SECRETS = {
    "slack": 'slack = "xoxb-' + "123456789012-1234567890123-" + 'AbCdEfGhIjKlMnOp"\n',
    "pem": 'k = """-----BEGIN RSA ' + 'PRIVATE KEY-----\nMIIEow\n"""\n',
    "pem-openssh": 'k = "-----BEGIN OPENSSH ' + 'PRIVATE KEY-----"\n',
    "ghp": 'x = "ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"\n',
    "gho": 'x = "gho_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"\n',
    "github_pat": 'x = "github_pat_' + '11ABCDEFG0123456789_abcdefghijklmnop"\n',
    "generic-token": 'MY_API_TOKEN = "q8Zr2LxP0vN7kT4wB9mC"\n',
    "generic-secret": 'client_secret = "' + "Zx9Lq2Vw8R" + 't5Yp3Nm6Kb"\n',
}


@pytest.mark.parametrize("name", list(SECRETS))
@pytest.mark.parametrize("language", ["python", "javascript"])
async def test_hardcoded_secrets_are_unsafe_at_every_level(service, name, language):
    for level in SecurityLevel:
        result = await _validate(service, SECRETS[name], language=language, level=level)
        assert result.is_safe is False, (name, level)


# --- JavaScript -----------------------------------------------------------------

JS_UNSAFE = {
    "spawn-shell": "const { spawn } = require('child_process');\nspawn(cmd, { shell: true });\n",
    "execSync": "const cp = require('child_process');\ncp.execSync(cmd);\n",
    "destructured-exec": "const { exec } = require('child_process');\nexec(cmd);\n",
    "import-exec": "import { exec } from 'child_process';\nexec(cmd);\n",
    "eval": "eval(userInput);\n",
    "eval-alias": "const run = eval;\nrun(code);\n",
    "new-Function": "const f = new Function('a', body);\n",
    "Function": "const f = Function('return ' + body);\n",
    "vm.runInThisContext": "const vm = require('vm');\nvm.runInThisContext(code);\n",
    "vm.runInNewContext": "const vm = require('vm');\nvm.runInNewContext(code);\n",
    "require-var": "const m = require(name);\n",
    "import-var": "const m = await import(name);\n",
    "query-template": "db.query(`SELECT * FROM u WHERE id=${req.params.id}`);\n",
    "query-concat": "conn.query('SELECT * FROM u WHERE id=' + id);\n",
}


@pytest.mark.parametrize("name", list(JS_UNSAFE))
@pytest.mark.parametrize("level", [SecurityLevel.MEDIUM, SecurityLevel.HIGH])
async def test_js_dangerous_code_is_unsafe(service, name, level):
    result = await _validate(service, JS_UNSAFE[name], language="javascript", level=level)
    assert result.is_safe is False, (name, result.violations)


JS_CLEAN = {
    "express": "const express = require('express');\nconst app = express();\n",
    "regex-exec": "const m = /a(b)/.exec(s);\n",
    "function-expr": "const f = function (a) { return a + 1; };\n",
    "param-query": "db.query('SELECT * FROM u WHERE id = ?', [id]);\n",
    "evaluate-word": "const evaluation = evaluate(x);\n",
}


@pytest.mark.parametrize("name", list(JS_CLEAN))
async def test_js_clean_controls_stay_safe(service, name):
    result = await _validate(service, JS_CLEAN[name], language="javascript")
    assert result.is_safe is True, (name, result.violations)


# --- budget: any input <= 200k chars on the 2 s fast path, linear beyond ------
# A bare wall/CPU budget flakes on a contended host: measured 2026-11-05 on the
# single CI node with several jobs queued, this test's own `a-lines` cases took
# 2.07-3.14 CPU-seconds while the same commits passed on an idle node.
# `tests.cpu_budget.is_linear` is the house tool for exactly that: 2 s stays the
# fast path, and only when it is exceeded does it check the PROPERTY — doubling
# the 200 KB input must not more than triple the CPU cost (linear ~2x) — under a
# hard cap of 10x. A contended host inflates both measurements alike, so the
# ratio holds; the pre-fix pathological inputs (~40-52 s) blow the cap.

N = 199_999


def _rep(unit: str) -> str:
    return (unit * (N // len(unit) + 1))[:N]


ADVERSARIAL = {
    "secret": _rep("secret"),
    "token": _rep("token"),
    "_token": _rep("_token"),
    "password-sq": _rep("password = '"),
    "password-dq": _rep('password = "'),
    "a-lines": _rep("a\n"),
    "x=1-lines": _rep("x=1\n"),
    "AKIA": _rep("AKIA"),
    "xoxb": _rep("xoxb-"),
    "pem": _rep("-----BEGIN "),
    "ghp": _rep("ghp_"),
    "dotted": _rep("a."),
    "token-assign": _rep('my_token = "q8Zr2LxP0vN7kT4wB9mC"\n'),
    "alias-exec": _rep("import os as o\no.system(x)\n"),
    "fstring-execute": _rep('cur.execute(f"{x}")\n'),
    "concat-chain": "x = " + '"a" + ' * 30_000 + '"a"\n',
    "attr-chain": "x = a" + ".a" * 60_000 + "\n",
    "child_process": _rep("child_process "),
    "require(": _rep("require("),
    "query(`": _rep(".query(`"),
}


@pytest.fixture
def no_real_engines(monkeypatch):
    """The real app wiring, with every engine class booby-trapped."""

    async def _boom(self, *a, **k):
        raise AssertionError("/validate invoked an external engine")

    for cls in (BanditScanner, SecretsScanner, SemgrepScanner, IaCScanner):
        monkeypatch.setattr(cls, "scan", _boom)


@pytest.mark.parametrize("language", ["python", "javascript"])
@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_http_validate_meets_the_cpu_budget(
    test_client, tenant_headers, no_real_engines, name, language
):
    responses = []

    def post(code: str) -> None:
        responses.append(
            test_client.post(
                "/api/security/validate",
                json={"code": code, "language": language, "security_level": "medium"},
                headers=tenant_headers,
            )
        )

    ok, detail = is_linear(post, ADVERSARIAL[name], 2.0)
    assert ok, f"{name}/{language}: {detail}"
    response = responses[-1]
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    assert set(body["validation"]) >= {"is_safe", "violations", "risk_score"}
