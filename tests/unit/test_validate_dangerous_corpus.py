"""Regression: no dangerous snippet may become SAFE where origin/main said UNSAFE.

bb8bad7 lowered `import os` to a LOW capability hint. On main, that import (then
HIGH) was the only signal pushing `getattr(os, "sys"+"tem")(user)` and
`os.remove(user_path)` over the MEDIUM threshold — so lowering it turned both
from unsafe (risk 80 / 60) to safe (40 / 20). 20 (snippet, level) pairs of the
corpus below regressed that way.

``MAIN_UNSAFE`` is origin/main's verdict (0679e93), measured by running
origin/main's own src/ (copied out of the repo) over this exact corpus with a
single service instance, as in production. A level listed there must stay
unsafe; a level not listed may go either way (several got stricter on purpose).
"""

from __future__ import annotations

import pytest

from config.security_config import SystemSecurityConfig
from models.security_models import SecurityLevel, SecurityValidationRequest
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService

PY = {
    "os_system": "import os\nos.system(user)\n",
    "os_popen": "import os\nos.popen(user).read()\n",
    "os_execv": "import os\nos.execv('/bin/sh', [user])\n",
    "os_spawn": "import os\nos.spawnl(os.P_WAIT, user)\n",
    "getattr_os_system": 'import os\ngetattr(os, "sys"+"tem")(user)\n',
    "getattr_os_literal": 'import os\ngetattr(os, "system")(user)\n',
    "os_remove": "import os\nos.remove(user_path)\n",
    "os_unlink": "import os\nos.unlink(user_path)\n",
    "os_rmdir": "import os\nos.rmdir(user_path)\n",
    "os_removedirs": "import os\nos.removedirs(user_path)\n",
    "os_rename": "import os\nos.rename(a, b)\n",
    "os_replace": "import os\nos.replace(a, b)\n",
    "os_chmod": "import os\nos.chmod(p, 0o777)\n",
    "os_chown": "import os\nos.chown(p, 0, 0)\n",
    "os_kill": "import os\nos.kill(pid, 9)\n",
    "shutil_rmtree": "import shutil\nshutil.rmtree(user_path)\n",
    "shutil_move": "import shutil\nshutil.move(a, b)\n",
    "subprocess_run": "import subprocess\nsubprocess.run(user, shell=True)\n",
    "from_subprocess": "from subprocess import Popen\nPopen(user)\n",
    "eval": "eval(user)\n",
    "exec": "exec(user)\n",
    "compile": "compile(user, 'x', 'exec')\n",
    "dunder_import": "__import__('os').system(user)\n",
    "dunder_import_var": "m = __import__(name)\n",
    "importlib_var": "import importlib\nm = importlib.import_module(name)\n",
    "importlib_from": "from importlib import import_module\nm = import_module(name)\n",
    "builtins_getattr": "import builtins\ngetattr(builtins, 'ev'+'al')(user)\n",
    "dunder_builtins": "__builtins__['eval'](user)\n",
    "globals_index": "globals()['__builtins__']\n",
    "vars_index": "vars(__builtins__)['eval'](user)\n",
    "pickle_loads": "import pickle\npickle.loads(data)\n",
    "open_write": "open('/etc/passwd', 'w').write(x)\n",
    "sqli": 'cur.execute("SELECT * FROM t WHERE id = " + uid)\n',
    "secret": 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',  # pragma: allowlist secret
    "socket": "import socket\ns = socket.socket()\n",
    "ctypes": "import ctypes\nctypes.CDLL(None)\n",
    "sys_modules": "import sys\nsys.modules['os'].system(user)\n",
    "getattr_subprocess": "import subprocess\ngetattr(subprocess, name)(user)\n",
}
JS = {
    "js_eval": "eval(user)\n",
    "js_function": "new Function(user)()\n",
    "js_child_process": "const cp = require('child_process'); cp.exec(user)\n",
    "js_process_env": "process.exit(1)\n",
    "js_settimeout_str": "setTimeout('alert(1)', 10)\n",
    "js_innerhtml": "el.innerHTML = user\n",
}

# origin/main 0679e93: levels at which each snippet was UNSAFE.
MAIN_UNSAFE: dict[str, tuple[str, ...]] = {
    "os_system": ("low", "medium", "high"),
    "os_popen": ("medium", "high"),
    "os_execv": ("medium", "high"),
    "os_spawn": ("medium", "high"),
    "getattr_os_system": ("medium", "high"),
    "getattr_os_literal": ("medium", "high"),
    "os_remove": ("medium", "high"),
    "os_unlink": ("medium", "high"),
    "os_rmdir": ("medium", "high"),
    "os_removedirs": ("medium", "high"),
    "os_rename": ("medium", "high"),
    "os_replace": ("medium", "high"),
    "os_chmod": ("medium", "high"),
    "os_chown": ("medium", "high"),
    "os_kill": ("medium", "high"),
    "shutil_rmtree": ("high",),
    "shutil_move": ("high",),
    "subprocess_run": ("low", "medium", "high"),
    "from_subprocess": ("high",),
    "eval": ("low", "medium", "high"),
    "exec": ("low", "medium", "high"),
    "compile": ("low", "medium", "high"),
    "dunder_import": ("high",),
    "dunder_import_var": ("high",),
    "importlib_var": (),
    "importlib_from": (),
    "builtins_getattr": (),
    "dunder_builtins": ("low", "medium", "high"),
    "globals_index": ("low", "medium", "high"),
    "vars_index": ("low", "medium", "high"),
    "pickle_loads": ("high",),
    "open_write": (),
    "sqli": (),
    "secret": (),
    "socket": ("high",),
    "ctypes": ("high",),
    "sys_modules": ("high",),
    "getattr_subprocess": ("high",),
    "js_eval": ("low", "medium", "high"),
    "js_function": ("low", "medium", "high"),
    "js_child_process": (),
    "js_process_env": ("high",),
    "js_settimeout_str": ("high",),
    "js_innerhtml": (),
}

# Rules added for the dynamic-access / destructive-call classes: unsafe at
# MEDIUM and HIGH whatever main said.
MUST_BE_UNSAFE_AT_MEDIUM_AND_HIGH = [
    "getattr_os_system",
    "getattr_os_literal",
    "getattr_subprocess",
    "builtins_getattr",
    "os_remove",
    "os_unlink",
    "os_rmdir",
    "os_removedirs",
    "os_rename",
    "os_replace",
    "os_chmod",
    "os_chown",
    "os_kill",
    "shutil_rmtree",
    "shutil_move",
    "dunder_import",
    "dunder_import_var",
    "importlib_var",
    "importlib_from",
    "globals_index",
    "vars_index",
    "sys_modules",
]


class _CleanEngine:
    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        return []


@pytest.fixture(scope="module")
def service() -> SystemSecurityService:
    d = SecurityVulnerabilityDetector()
    for name in ("_bandit", "_secrets", "_semgrep", "_iac", "_image"):
        setattr(d, name, _CleanEngine())
    return SystemSecurityService(SystemSecurityConfig(), None, detector=d)


def _cases():
    for name, code in PY.items():
        yield name, code, "python"
    for name, code in JS.items():
        yield name, code, "javascript"


@pytest.mark.parametrize(("name", "code", "language"), list(_cases()), ids=lambda v: str(v)[:24])
async def test_never_safe_where_main_was_unsafe(service, name, code, language):
    for level in MAIN_UNSAFE[name]:
        result = await service.validate_code_security(
            SecurityValidationRequest(code=code, language=language, security_level=level)
        )
        assert result.is_safe is False, f"{name} became SAFE at {level} (unsafe on main)"


def test_corpus_is_large_enough():
    assert len(PY) + len(JS) >= 30
    assert sum(1 for levels in MAIN_UNSAFE.values() if levels) >= 30


@pytest.mark.parametrize("name", MUST_BE_UNSAFE_AT_MEDIUM_AND_HIGH)
@pytest.mark.parametrize("level", [SecurityLevel.MEDIUM, SecurityLevel.HIGH])
async def test_dynamic_access_and_destructive_calls_are_unsafe(service, name, level):
    result = await service.validate_code_security(
        SecurityValidationRequest(code=PY[name], language="python", security_level=level)
    )
    assert result.is_safe is False


@pytest.mark.parametrize(
    "code",
    [
        'import importlib\nm = importlib.import_module("json")\n',
        'x = getattr(obj, "name", None)\n',
    ],
    ids=["import_module-literal", "getattr-plain-object"],
)
@pytest.mark.parametrize("level", [SecurityLevel.LOW, SecurityLevel.MEDIUM])
async def test_benign_controls_stay_safe(service, code, level):
    """Controls: the new rules must not fire on ordinary os / getattr use."""
    result = await service.validate_code_security(
        SecurityValidationRequest(code=code, language="python", security_level=level)
    )
    assert result.is_safe is True, result.violations


@pytest.mark.parametrize(
    "code",
    ["import os\nprint(os.getcwd())\n", "import os\npath = os.path.join(a, b)\n"],
    ids=["os.getcwd", "os.path.join"],
)
async def test_benign_os_use_keeps_mains_verdict(service, code):
    """`import os` is HIGH, as on origin/main (no rule may be weaker than main):
    benign os use is safe at LOW and, exactly as on main (risk 60), unsafe at
    MEDIUM. That main false positive is accepted; no new rule adds to it."""
    low = await service.validate_code_security(
        SecurityValidationRequest(code=code, language="python", security_level=SecurityLevel.LOW)
    )
    assert low.is_safe is True
    medium = await service.validate_code_security(
        SecurityValidationRequest(code=code, language="python", security_level=SecurityLevel.MEDIUM)
    )
    assert medium.risk_score == 60
    assert all(v.severity != SecurityLevel.CRITICAL for v in medium.violations)
