"""In-process rules for the inline ``/validate`` gate.

Two analyses that a line-by-line regex table cannot do:

* :func:`analyze_python_calls` — an AST pass that resolves import aliases
  (``import os as o``, ``from os import system as run``,
  ``from subprocess import Popen as P``, ``e = eval``) and flags CALLS to
  dangerous qualified names. ``o.execvp(...)`` and ``run(cmd)`` are
  ``os.execvp`` and ``os.system``; the literal table only sees ``os.``.
* :func:`generic_secret_violations` — a credential-named assignment of a long,
  high-entropy literal (``GITHUB_TOKEN = "..."``), checked by entropy rather
  than by a provider-specific shape.

Everything here is linear in the input and runs in-process: no subprocess, no
file I/O.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter

from models.security_models import SecurityLevel, SecurityViolation

# Categories the service treats as blocking at MEDIUM and above when HIGH
# (see security_service.BLOCKING_HIGH_CATEGORIES).
CAT_PROCESS = "process_execution"
CAT_CODE = "code_execution"
CAT_DESERIALIZATION = "insecure_deserialization"
CAT_SQL = "sql_injection"
CAT_DYNAMIC_IMPORT = "dynamic_import"
CAT_DYNAMIC_ACCESS = "dynamic_dangerous_access"
CAT_REVERSE_SHELL = "reverse_shell"
CAT_NATIVE = "native_code"
CAT_DESTRUCTIVE = "destructive_os_call"

_OS_MODULES = frozenset({"os", "posix", "nt"})
_DANGEROUS_ATTR_TARGETS = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "builtins",
        "__builtins__",
        "sys",
        "shutil",
        "importlib",
        "pty",
        "ctypes",
    }
)
_SUBPROCESS_FUNCS = frozenset(
    {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
)
_DESERIALIZERS = frozenset(
    {
        "pickle.loads",
        "pickle.load",
        "pickle.Unpickler",
        "_pickle.loads",
        "_pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "dill.loads",
        "dill.load",
        "marshal.loads",
        "marshal.load",
        "shelve.open",
        "jsonpickle.decode",
        "pandas.read_pickle",
        "yaml.unsafe_load",
        "yaml.unsafe_load_all",
        "yaml.full_load",
        "yaml.full_load_all",
    }
)
_YAML_SAFE_LOADERS = frozenset(
    {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader"}
)
_NATIVE_LOADERS = frozenset(
    {
        "ctypes.CDLL",
        "ctypes.PyDLL",
        "ctypes.WinDLL",
        "ctypes.OleDLL",
        "ctypes.cdll.LoadLibrary",
        "ctypes.windll.LoadLibrary",
        "ctypes.pydll.LoadLibrary",
        "ctypes.util.find_library",
    }
)
_DESTRUCTIVE = frozenset(
    {
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "renames",
        "replace",
        "chmod",
        "lchmod",
        "fchmod",
        "chown",
        "lchown",
        "fchown",
        "kill",
        "killpg",
        "truncate",
        "ftruncate",
    }
)
_SQL_SINKS = frozenset({"execute", "executemany", "executescript", "raw"})
_SQL_KEYWORD = re.compile(
    r"\b(?:select|insert|update|delete|drop|create|alter|replace|merge|truncate|union)\b",
    re.IGNORECASE,
)


def _v(
    node: ast.AST,
    severity: SecurityLevel,
    category: str,
    matched: str,
    description: str,
    fix: str,
) -> SecurityViolation:
    return SecurityViolation(
        type=category,
        severity=severity,
        line_number=getattr(node, "lineno", None),
        pattern_matched=matched,
        description=description,
        suggested_fix=fix,
    )


def _is_str_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _is_literal_argv(node: ast.AST | None) -> bool:
    """A string literal or a list/tuple made only of string literals."""
    if _is_str_literal(node):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_str_literal(e) for e in node.elts)
    return False


# Hard bound on the AST work one /validate request may cause. A module with
# more (non-context) nodes than this is not analysed: the result is degraded
# and therefore never "safe" (see SystemSecurityService). Real code measures
# ~12-19k nodes per 200k chars (this package, pydantic); 100k is only reached
# by synthetic node-dense input (``"f(a)\n" * 40000``).
MAX_AST_NODES = 100_000
AST_BUDGET_PATTERN = "ast_budget_exceeded"
# A qualified name with more parts than this is not a module/function path a
# rule can name; refusing it keeps resolution linear on `x.a.a.a...` chains.
_MAX_QUALNAME_PARTS = 24

# `from M import *` of these binds their dangerous callables as bare names.
_STAR_DANGEROUS_MODULES = frozenset(
    {"os", "posix", "nt", "subprocess", "pty", "builtins", "pickle", "marshal", "ctypes"}
)
# sys.modules[<key>] / sys.modules.get(<key>) of these is a reach into them.
_DANGEROUS_MODULE_KEYS = frozenset(
    {"os", "posix", "nt", "subprocess", "builtins", "__builtins__", "pty", "ctypes", "importlib"}
)
# Attribute names whose only use is escaping the namespace a reader can see.
_INTROSPECTION_ATTRS = frozenset({"__subclasses__", "__globals__"})
# Modules whose namespace dict (M.__dict__) is a lookup of their callables.
_NAMESPACE_DICT_TARGETS = _DANGEROUS_ATTR_TARGETS - {"sys", "shutil", "importlib"}
_DANGEROUS_CALLABLE_NAMES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "pty.spawn",
        "commands.getoutput",
        "commands.getstatusoutput",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "platform.popen",
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "_pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "dill.loads",
        "dill.load",
        "marshal.loads",
        "marshal.load",
    }
)


def is_dangerous_callable(q: str) -> bool:
    """``q`` (alias-resolved) names a process/code-execution/unpickling callable."""
    mod, _, attr = q.rpartition(".")
    if mod in _OS_MODULES and (
        attr in ("system", "popen") or attr.startswith(("exec", "spawn", "posix_spawn"))
    ):
        return True
    if mod == "subprocess" and attr in _SUBPROCESS_FUNCS:
        return True
    return q in _DANGEROUS_CALLABLE_NAMES


class AstBudgetExceededError(Exception):
    """The module has more AST nodes than :data:`MAX_AST_NODES`."""


def _collect_nodes(tree: ast.AST, budget: int) -> tuple[list[ast.AST], set[int]]:
    """Every non-context node in BFS order (parents first), plus the ids of
    nodes that are the ``func`` of a Call. One walk; raises past ``budget``."""
    nodes: list[ast.AST] = []
    call_funcs: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.expr_context):
            continue
        nodes.append(n)
        if len(nodes) > budget:
            raise AstBudgetExceededError
        if isinstance(n, ast.Call):
            call_funcs.add(id(n.func))
    return nodes, call_funcs


def _is_sql_build(node: ast.AST) -> bool:
    return _tainted_string_build(node) and bool(_SQL_KEYWORD.search(_literal_text(node)))


class _Resolver:
    """Maps local names to the qualified names they were imported/assigned as.

    Built in ONE pass over the collected nodes. Everything a rule later asks
    (alias of a name, "was this name ever bound to a built SQL string") is a
    dict/set lookup, so the analysis stays linear in the module size: the
    previous per-sink rescan of every build of the name was quadratic
    (``"q='a'+b\\nc.execute(q)\\n" * n``: 50k chars took 13 s).
    """

    def __init__(self, nodes: list[ast.AST]) -> None:
        self.aliases: dict[str, str] = {}
        # Names bound (anywhere in the module) to a SQL string built from
        # non-literal parts. Flow-insensitive, like the alias map.
        self.sql_built: set[str] = set()
        self.imported_modules: set[str] = set()
        self.star_modules: list[str] = []
        self._memo: dict[int, str | None] = {}
        assigns: list[ast.Assign] = []
        for node in nodes:
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.imported_modules.add(a.name.split(".")[0])
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.aliases.setdefault(top, top)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self.imported_modules.add(node.module.split(".")[0])
                for a in node.names:
                    if a.name == "*":
                        self.star_modules.append(node.module)
                        continue
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, ast.Assign):
                assigns.append(node)
                if any(isinstance(t, ast.Name) for t in node.targets) and _is_sql_build(node.value):
                    self.sql_built.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                if (
                    isinstance(node.target, ast.Name)
                    and node.value is not None
                    and _is_sql_build(node.value)
                ):
                    self.sql_built.add(node.target.id)
            elif (
                isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Name)
                and _is_sql_build(ast.BinOp(left=node.target, op=node.op, right=node.value))
            ):
                self.sql_built.add(node.target.id)
        # Assignment aliases (``e = eval``, ``run = os.system``); two rounds so a
        # short chain (``a = os; b = a.system``) resolves. Each lookup is
        # depth-bounded, so this is linear in the number of assignments.
        for _ in range(2):
            for node in assigns:
                if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                    continue
                name = node.targets[0].id
                if isinstance(node.value, (ast.Name, ast.Attribute)):
                    q = self._qualname(node.value, 0, memo=False)
                    if q and q != name:
                        self.aliases[name] = q

    def _bare_name(self, ident: str) -> str:
        q = self.aliases.get(ident)
        if q is None:
            # `from os import *` binds os.system as `system`.
            for mod in self.star_modules:
                if is_dangerous_callable(f"{mod}.{ident}"):
                    return f"{mod}.{ident}"
            q = ident
        return q[len("builtins.") :] if q.startswith("builtins.") else q

    def qualname(self, node: ast.AST) -> str | None:
        """Alias-resolved dotted name of ``node`` (memoised per node; callers
        visit children before parents, so no lookup recurses deeply)."""
        return self._qualname(node, 0, memo=True)

    def _qualname(self, node: ast.AST, depth: int, memo: bool) -> str | None:
        if memo:
            key = id(node)
            if key in self._memo:
                return self._memo[key]
        q = self._compute(node, depth, memo)
        if q is not None and q.count(".") >= _MAX_QUALNAME_PARTS:
            q = None
        if memo:
            self._memo[id(node)] = q
        return q

    def _compute(self, node: ast.AST, depth: int, memo: bool) -> str | None:
        if depth > _MAX_QUALNAME_PARTS:
            return None
        if isinstance(node, ast.Name):
            return self._bare_name(node.id)
        if isinstance(node, ast.Attribute):
            base = self._qualname(node.value, depth + 1, memo)
            if base is None:
                return None
            if base in ("builtins", "__builtins__") and node.attr != "__dict__":
                return node.attr
            return f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            # importlib.import_module("os") / __import__("os") /
            # sys.modules.get("os") evaluate to os.
            fn = self._qualname(node.func, depth + 1, memo)
            if fn in (
                "importlib.import_module",
                "__import__",
                "importlib.__import__",
                "sys.modules.get",
            ):
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
            return None
        if isinstance(node, ast.Subscript):
            # sys.modules["os"] is os.
            key = node.slice
            if (
                self._qualname(node.value, depth + 1, memo) == "sys.modules"
                and isinstance(key, ast.Constant)
                and isinstance(key.value, str)
            ):
                return key.value
        return None


def _tainted_string_build(node: ast.AST) -> bool:
    """A string built from non-literal parts: f-string, ``+``, ``%``, ``.format``."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        if isinstance(node.op, ast.Mod):
            return (
                _is_str_literal(node.left) or isinstance(node.left, ast.JoinedStr)
            ) and not _is_str_literal(node.right)
        leaves = _add_leaves(node)
        return any(_is_str_literal(x) or isinstance(x, ast.JoinedStr) for x in leaves) and any(
            not _is_str_literal(x) for x in leaves
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_str_literal(node.func.value)
    ):
        return bool(node.args or node.keywords)
    return False


def _add_leaves(node: ast.AST) -> list[ast.AST]:
    out: list[ast.AST] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            stack.extend((n.left, n.right))
        else:
            out.append(n)
    return out


def _literal_text(node: ast.AST) -> str:
    """Concatenated literal parts of a string build (for the SQL keyword check)."""
    parts: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(n.value)
    return " ".join(parts)


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _budget_violation(limit: int) -> SecurityViolation:
    return SecurityViolation(
        type="analysis_incomplete",
        severity=SecurityLevel.MEDIUM,
        line_number=None,
        pattern_matched=AST_BUDGET_PATTERN,
        description=f"Module exceeds {limit} AST nodes: alias/call analysis did not run",
        suggested_fix="Validate smaller units of code",
    )


def analyze_python_calls(tree: ast.AST, max_nodes: int = MAX_AST_NODES) -> list[SecurityViolation]:
    """Flag dangerous calls AND dangerous callables used as values, resolving
    import aliases. Linear: one collection walk (bounded by ``max_nodes``), one
    resolver pass, one analysis pass in which every name lookup is memoised.

    Past ``max_nodes`` the only finding is :data:`AST_BUDGET_PATTERN`, which the
    service turns into a degraded (never safe) result.
    """
    try:
        nodes, call_funcs = _collect_nodes(tree, max_nodes)
    except AstBudgetExceededError:
        return [_budget_violation(max_nodes)]
    r = _Resolver(nodes)
    out: list[SecurityViolation] = []
    socket_imported = "socket" in r.imported_modules
    # Children before parents: every qualname() a check asks for is memoised.
    for node in reversed(nodes):
        if isinstance(node, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
            r.qualname(node)
        if isinstance(node, ast.Call):
            _check_call(node, r, socket_imported, out)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            _check_reference(node, r, call_funcs, out)
        elif isinstance(node, ast.Subscript):
            _check_subscript(node, r, out)
        elif (
            isinstance(node, ast.ImportFrom)
            and not node.level
            and node.module in _STAR_DANGEROUS_MODULES
            and any(a.name == "*" for a in node.names)
        ):
            out.append(
                _v(
                    node,
                    SecurityLevel.HIGH,
                    CAT_DYNAMIC_ACCESS,
                    f"from {node.module} import *",
                    f"Star import binds {node.module}'s process/code-execution callables "
                    "under bare names",
                    f"Import the names you use from {node.module} explicitly",
                )
            )
    out.sort(key=lambda v: v.line_number or 0)
    return out


def _check_reference(
    node: ast.Name | ast.Attribute,
    r: _Resolver,
    call_funcs: set[int],
    out: list[SecurityViolation],
) -> None:
    """A dangerous callable taken as a VALUE (``s, = (os.system,)``,
    ``[os.system]``, ``partial(os.system)``, ``def f(e=eval)``), plus
    namespace-escape attributes (``os.__dict__``, ``x.__subclasses__``)."""
    if isinstance(node, ast.Attribute):
        if node.attr in _INTROSPECTION_ATTRS:
            out.append(
                _v(
                    node,
                    SecurityLevel.CRITICAL,
                    CAT_DYNAMIC_ACCESS,
                    f".{node.attr}",
                    f"Object-graph introspection ({node.attr}) reaches arbitrary classes/globals",
                    "Do not walk the object graph from validated code",
                )
            )
            return
        if node.attr == "__dict__":
            base = r.qualname(node.value)
            if base in _NAMESPACE_DICT_TARGETS:
                out.append(
                    _v(
                        node,
                        SecurityLevel.CRITICAL,
                        CAT_DYNAMIC_ACCESS,
                        f"{base}.__dict__",
                        f"Namespace lookup on {base}: reaches its callables by name",
                        "Use direct, reviewable attribute access",
                    )
                )
                return
    if not isinstance(node.ctx, ast.Load) or id(node) in call_funcs:
        return  # a call: _check_call grades it with its arguments
    q = r.qualname(node)
    if q and is_dangerous_callable(q):
        out.append(
            _v(
                node,
                SecurityLevel.CRITICAL,
                CAT_DYNAMIC_ACCESS,
                q,
                f"Dangerous callable {q} used as a value (aliased, stored or passed)",
                f"Do not reference {q} from validated code",
            )
        )


def _sys_modules_key_finding(
    node: ast.AST, key: ast.AST | None, out: list[SecurityViolation]
) -> None:
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        if key.value.split(".")[0] in _DANGEROUS_MODULE_KEYS:
            out.append(
                _v(
                    node,
                    SecurityLevel.CRITICAL,
                    CAT_DYNAMIC_ACCESS,
                    f"sys.modules[{key.value!r}]",
                    f"Module {key.value} reached through sys.modules",
                    "Import modules statically",
                )
            )
    elif not (isinstance(key, ast.Name) and key.id == "__name__"):
        out.append(
            _v(
                node,
                SecurityLevel.HIGH,
                CAT_DYNAMIC_IMPORT,
                "sys.modules[<computed>]",
                "Module looked up in sys.modules by a computed name",
                "Import modules statically",
            )
        )


def _check_subscript(node: ast.Subscript, r: _Resolver, out: list[SecurityViolation]) -> None:
    base = r.qualname(node.value)
    if base == "sys.modules":
        _sys_modules_key_finding(node, node.slice, out)
    elif base in ("__builtins__", "builtins", "__builtins__.__dict__", "builtins.__dict__"):
        out.append(
            _v(
                node,
                SecurityLevel.CRITICAL,
                CAT_DYNAMIC_ACCESS,
                f"{base}[...]",
                "Builtins looked up by name",
                "Use direct, reviewable names",
            )
        )


def _check_call(
    node: ast.Call, r: _Resolver, socket_imported: bool, out: list[SecurityViolation]
) -> None:
    q = r.qualname(node.func)
    first = node.args[0] if node.args else None

    # --- SQL built from non-literal parts passed to a query sink ---------
    if isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_SINKS and first:
        tainted = _tainted_string_build(first) or (
            isinstance(first, ast.Name) and first.id in r.sql_built
        )
        if tainted:
            out.append(
                _v(
                    node,
                    SecurityLevel.HIGH,
                    CAT_SQL,
                    f"{node.func.attr}(<built string>)",
                    "SQL query built from non-literal parts (f-string, +, %, .format)",
                    "Use a parameterized query: execute(sql, params)",
                )
            )
    if q is None:
        return
    mod, _, attr = q.rpartition(".")

    # --- OS process execution --------------------------------------------
    if mod in _OS_MODULES and (
        attr in ("system", "popen") or attr.startswith(("exec", "spawn", "posix_spawn"))
    ):
        out.append(
            _v(
                node,
                SecurityLevel.CRITICAL,
                CAT_PROCESS,
                q,
                f"OS process execution: {q}",
                "Do not spawn processes from validated code",
            )
        )
    elif q in ("pty.spawn", "commands.getoutput", "commands.getstatusoutput") or q in (
        "asyncio.create_subprocess_shell",
        "platform.popen",
    ):
        out.append(
            _v(
                node,
                SecurityLevel.CRITICAL,
                CAT_PROCESS,
                q,
                f"Shell / pseudo-terminal execution: {q}",
                "Do not spawn shells from validated code",
            )
        )
    elif (mod == "subprocess" and attr in _SUBPROCESS_FUNCS) or q in (
        "asyncio.create_subprocess_exec",
    ):
        shell = _kw(node, "shell")
        shell_on = shell is not None and not (
            isinstance(shell, ast.Constant) and shell.value in (False, None, 0)
        )
        argv = first if first is not None else _kw(node, "args")
        if shell_on or attr in ("getoutput", "getstatusoutput"):
            sev = SecurityLevel.CRITICAL
            desc = f"Shell command execution: {q}"
        elif not _is_literal_argv(argv):
            sev = SecurityLevel.HIGH
            desc = f"Process execution with a non-literal command: {q}"
        else:
            sev = SecurityLevel.MEDIUM
            desc = f"Process execution: {q}"
        out.append(_v(node, sev, CAT_PROCESS, q, desc, "Avoid shell=True; pass a fixed argv list"))
    elif mod in _OS_MODULES and attr == "dup2":
        if socket_imported:
            out.append(
                _v(
                    node,
                    SecurityLevel.CRITICAL,
                    CAT_REVERSE_SHELL,
                    q,
                    "os.dup2 with a socket in scope: reverse-shell stdio redirection",
                    "Do not redirect process stdio to a network socket",
                )
            )
        else:
            out.append(
                _v(
                    node,
                    SecurityLevel.MEDIUM,
                    CAT_PROCESS,
                    q,
                    "File descriptor redirection (os.dup2)",
                    "Review stdio redirection",
                )
            )
    elif (mod in _OS_MODULES and attr in _DESTRUCTIVE) or q in (
        "shutil.rmtree",
        "shutil.move",
        "shutil.chown",
    ):
        out.append(
            _v(
                node,
                SecurityLevel.HIGH,
                CAT_DESTRUCTIVE,
                q,
                f"Destructive filesystem / process operation: {q}",
                "Do not delete, move or re-permission files from validated code",
            )
        )
    elif mod in _OS_MODULES and attr in ("fork", "forkpty"):
        out.append(
            _v(
                node,
                SecurityLevel.MEDIUM,
                CAT_PROCESS,
                q,
                f"Process fork: {q}",
                "Avoid forking from validated code",
            )
        )

    # --- dynamic code execution ------------------------------------------
    elif q in ("eval", "exec", "compile"):
        literal = _is_str_literal(first)
        out.append(
            _v(
                node,
                SecurityLevel.HIGH if literal else SecurityLevel.CRITICAL,
                CAT_CODE,
                f"{q}()",
                f"Dynamic code execution: {q}" + ("" if literal else " of a non-literal argument"),
                f"Avoid {q}() in validated code",
            )
        )
    elif q in ("__import__", "importlib.import_module", "importlib.__import__"):
        if not _is_str_literal(first):
            out.append(
                _v(
                    node,
                    SecurityLevel.HIGH,
                    CAT_DYNAMIC_IMPORT,
                    f"{q}(<computed>)",
                    "Dynamic import of a computed module name",
                    "Import modules statically",
                )
            )
    elif q == "sys.modules.get":
        _sys_modules_key_finding(node, first, out)
    elif q in ("getattr", "setattr", "delattr", "vars") and first is not None:
        target = r.qualname(first)
        name = node.args[1] if len(node.args) > 1 else None
        literal_name = (
            name.value if isinstance(name, ast.Constant) and isinstance(name.value, str) else None
        )
        # getattr(sys, "frozen", False) names a harmless attribute; a literal
        # that IS a dangerous callable or a dunder, or any computed name
        # (getattr(os, "sys" + "tem")), is a reach into the module.
        harmless_literal = (
            q == "getattr"
            and literal_name is not None
            and not literal_name.startswith("__")
            and not is_dangerous_callable(
                literal_name
                if target in ("builtins", "__builtins__")
                else f"{target}.{literal_name}"
            )
            and not (target in ("sys",) and literal_name == "modules")
        )
        if target in _DANGEROUS_ATTR_TARGETS and not harmless_literal:
            out.append(
                _v(
                    node,
                    SecurityLevel.CRITICAL,
                    CAT_DYNAMIC_ACCESS,
                    f"{q}({target}, ...)",
                    f"Dynamic attribute access on {target}",
                    "Use direct, reviewable attribute access",
                )
            )

    # --- deserialization / native code -----------------------------------
    elif q in _DESERIALIZERS:
        out.append(
            _v(
                node,
                SecurityLevel.HIGH,
                CAT_DESERIALIZATION,
                q,
                f"Unsafe deserialization: {q}",
                "Deserialize untrusted data with a safe format (json, yaml.safe_load)",
            )
        )
    elif q in ("yaml.load", "yaml.load_all"):
        loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
        if loader is None or r.qualname(loader) not in _YAML_SAFE_LOADERS:
            out.append(
                _v(
                    node,
                    SecurityLevel.HIGH,
                    CAT_DESERIALIZATION,
                    q,
                    f"{q} without SafeLoader can construct arbitrary objects",
                    "Use yaml.safe_load",
                )
            )
    elif q in _NATIVE_LOADERS or (mod == "ctypes.cdll" or mod == "ctypes.windll"):
        out.append(
            _v(
                node,
                SecurityLevel.HIGH,
                CAT_NATIVE,
                q,
                f"Native library loading: {q}",
                "Do not load native libraries from validated code",
            )
        )


# --- generic high-entropy secrets ------------------------------------------

# A credential-ish name, then `=`/`:`, then a quoted literal. LINEAR: the name
# may only start at a word boundary (lookbehind) and is bounded; the literal is
# bounded and cannot contain a quote or whitespace; every whitespace run is
# atomic. (Two adjacent plain ``[ \t]*`` runs were quadratic: ``"rbuRBU" + " " *
# 20_000`` took 2 s, 200k chars ~200 s.)
_ASSIGN_LITERAL = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_.]{0,63})[\"']?(?>[ \t]*)"
    r"(?::(?>[ \t]*)[A-Za-z_.\[\] |]{0,40})?"
    r"(?>[ \t]*)[:=](?>[ \t]*)[rbuRBU]?[\"']([^\"'\s]{16,512})[\"']"
)
_SECRET_NAME = re.compile(r"(?:key|token|secret|passw(?:or)?d|credential|auth)", re.IGNORECASE)
_MIN_ENTROPY_BITS = 3.5


def _entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def generic_secret_violations(code: str) -> list[SecurityViolation]:
    """Credential-named assignment of a long, high-entropy, mixed-class literal."""
    out: list[SecurityViolation] = []
    line = 1
    pos = 0
    for n, m in enumerate(_ASSIGN_LITERAL.finditer(code)):
        if n >= 200:
            break
        name, value = m.group(1), m.group(2)
        if not _SECRET_NAME.search(name):
            continue
        has_alpha = any(c.isalpha() for c in value)
        has_digit = any(c.isdigit() for c in value)
        if not (has_alpha and has_digit) or _entropy(value) < _MIN_ENTROPY_BITS:
            continue
        line += code.count("\n", pos, m.start())
        pos = m.start()
        out.append(
            SecurityViolation(
                type="hardcoded_credentials",
                severity=SecurityLevel.HIGH,
                line_number=line,
                pattern_matched="generic_high_entropy_secret",
                description=f"High-entropy literal assigned to credential-named '{name}'",
                suggested_fix="Load secrets from the environment or a secret store",
            )
        )
    return out
