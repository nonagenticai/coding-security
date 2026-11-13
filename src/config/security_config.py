"""
Security configuration and utilities for the coding-security microservice.

This module provides centralized security-related configurations.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class SystemSecurityConfig:
    """Centralized security configuration."""

    # Allowed commands for subprocess execution
    ALLOWED_COMMANDS = {
        "git",
        "docker",
        "npm",
        "node",
        "python",
        "pip",
        "poetry",
    }

    # Maximum command execution timeout (seconds)
    MAX_EXECUTION_TIMEOUT = 300

    # Allowed file extensions for processing
    ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".md"}

    DANGEROUS_PATTERNS: dict[str, list[dict[str, str]]] = {
        "python": [
            {
                "pattern": r"import\s+os\b",
                "severity": "high",
                "description": "Direct OS access",
            },
            {
                "pattern": r"os\.system\s*\(",
                "severity": "critical",
                "description": "System command execution",
            },
            {
                "pattern": r"os\.(?:popen|exec[lv]p?e?|spawn\w*|posix_spawnp?)\s*\(",
                "severity": "critical",
                "description": "OS process execution",
            },
            {
                "pattern": r"subprocess\.",
                "severity": "critical",
                "description": "Subprocess execution",
            },
            {
                "pattern": r"eval\s*\(",
                "severity": "critical",
                "description": "Code evaluation",
            },
            {
                "pattern": r"exec\s*\(",
                "severity": "critical",
                "description": "Code execution",
            },
            {
                "pattern": r"__import__\s*\(",
                "severity": "high",
                "description": "Dynamic imports",
                "category": "dynamic_import",
            },
            # Dynamic reach into os/subprocess/builtins: getattr(os, "sys"+"tem")
            # IS os.system, spelled so the literal patterns above cannot see it.
            # Its own (critical) rule: no rule may rely on `import os` adding
            # enough risk score to cross a threshold.
            {
                # A literal, harmless attribute name (getattr(sys, "frozen", False))
                # is not a reach; a computed name, a dunder, or a literal that is
                # itself a process/code-execution callable is.
                "pattern": r"\bgetattr\s*\(\s*(?:os|posix|nt|subprocess|builtins|__builtins__|sys|shutil|importlib|pty|ctypes)\s*,"
                r"(?!\s*[rbuRBU]?[\"'](?!__|system|popen|exec|spawn|posix_spawn|run[\"']|call|check_|Popen"
                r"|getoutput|getstatusoutput|eval[\"']|compile[\"']|modules[\"']|import_module|CDLL|PyDLL|cdll|pydll)"
                r"[A-Za-z_]\w{0,60}[\"']\s*[,)])",
                "severity": "critical",
                "description": "Dynamic attribute access on a process/OS/builtins module",
                "category": "dynamic_dangerous_access",
            },
            {
                "pattern": r"\bvars\s*\(\s*(?:os|posix|nt|subprocess|builtins|__builtins__|sys|shutil|importlib)\s*\)",
                "severity": "critical",
                "description": "Namespace access on a process/OS/builtins module",
                "category": "dynamic_dangerous_access",
            },
            {
                "pattern": r"\b(?:globals|locals|vars)\s*\(\s*\)\s*\[",
                "severity": "high",
                "description": "Name lookup through globals()/locals()/vars()",
                "category": "dynamic_import",
            },
            {
                # Non-literal module name: import_module(name), not import_module("json").
                "pattern": r"\bimport_module\s*\(\s*(?![rbuRBU]?[\"'])",
                "severity": "high",
                "description": "Dynamic import of a computed module name",
                "category": "dynamic_import",
            },
            {
                "pattern": r"\bsys\.modules\s*\[",
                "severity": "high",
                "description": "Module lookup through sys.modules",
                "category": "dynamic_import",
            },
            # Destructive filesystem/process calls: HIGH, and never tolerated by
            # the risk threshold at MEDIUM and above (see
            # SystemSecurityService.BLOCKING_HIGH_CATEGORIES).
            {
                "pattern": r"\bos\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|chmod|lchmod|fchmod|chown|lchown|fchown|kill|killpg|truncate|ftruncate)\s*\(",
                "severity": "high",
                "description": "Destructive filesystem / process operation",
                "category": "destructive_os_call",
            },
            {
                "pattern": r"\bshutil\.(?:rmtree|move|chown)\s*\(",
                "severity": "high",
                "description": "Destructive filesystem operation",
                "category": "destructive_os_call",
            },
            {
                "pattern": r"open\s*\(",
                "severity": "medium",
                "description": "File operations",
            },
        ],
        "javascript": [
            {
                "pattern": r"eval\s*\(",
                "severity": "critical",
                "description": "Code evaluation",
            },
            {
                "pattern": r"Function\s*\(",
                "severity": "high",
                "description": "Dynamic function creation",
            },
            {
                "pattern": r"require\s*\(",
                "severity": "medium",
                "description": "Module loading",
            },
            {
                "pattern": r"process\.",
                "severity": "high",
                "description": "Process access",
            },
            # Process execution / code execution rules. Categories here are in
            # SystemSecurityService.BLOCKING_HIGH_CATEGORIES: a HIGH finding is
            # never tolerated by the risk threshold at MEDIUM and above.
            {
                # Any use of child_process (require/import/dynamic import):
                # exec/execSync/spawn after a destructure or alias is invisible
                # to a per-call pattern, the module name is not.
                "pattern": r"\bchild_process\b",
                "severity": "high",
                "description": "child_process: OS process execution",
                "category": "process_execution",
            },
            {
                "pattern": r"\bshell\s*:\s*true\b",
                "severity": "critical",
                "description": "Process spawned through a shell (shell: true)",
                "category": "process_execution",
            },
            {
                "pattern": r"\b(?:execSync|execFileSync|spawnSync)\s*\(",
                "severity": "high",
                "description": "Synchronous process execution",
                "category": "process_execution",
            },
            {
                "pattern": r"\bvm\s*\.\s*(?:runIn\w{0,20}Context|compileFunction|Script)\b|\brunIn(?:New|This)?Context\s*\(",
                "severity": "critical",
                "description": "vm module code execution",
                "category": "code_execution",
            },
            {
                # eval taken as a value (const e = eval; e(x)).
                "pattern": r"[=(,:]\s*eval\b(?!\s*\()",
                "severity": "critical",
                "description": "eval aliased as a value",
                "category": "code_execution",
            },
            {
                # Function(...) without `new` (case-sensitive: `function (` is
                # an ordinary function expression).
                "pattern": r"(?<![\w$.])(?-i:Function)\s*\(",
                "severity": "high",
                "description": "Function constructor",
                "category": "code_execution",
            },
            # Reaches into the process/global object a per-call rule cannot name.
            {
                "pattern": r"(?<![\w$.])(?:global|globalThis)\s*\[",
                "severity": "critical",
                "description": "Dynamic lookup on the global object (global[...] / globalThis[...])",
                "category": "code_execution",
            },
            {
                "pattern": r"\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(",
                "severity": "critical",
                "description": "process.binding/dlopen: native process internals",
                "category": "process_execution",
            },
            {
                "pattern": r"\.constructor\s*\.\s*constructor\s*\(",
                "severity": "critical",
                "description": "Function constructor reached through the prototype chain",
                "category": "code_execution",
            },
            {
                # require('child_' + 'process') / require(`${x}`): a computed
                # module name spelled to dodge the module-name rules.
                "pattern": r"\brequire\s*\(\s*(?:[\"'][^\"'\n]{0,200}[\"']\s*\+|`[^`\n]{0,200}\$\{)",
                "severity": "high",
                "description": "require() of a concatenated / interpolated module name",
                "category": "dynamic_import",
            },
            {
                "pattern": r"\brequire\s*\(\s*(?![\"'`\s])",
                "severity": "high",
                "description": "require() of a computed module name",
                "category": "dynamic_import",
            },
            {
                "pattern": r"(?<![\w$.])import\s*\(\s*(?![\"'`\s])",
                "severity": "high",
                "description": "Dynamic import() of a computed module name",
                "category": "dynamic_import",
            },
            {
                "pattern": r"\.(?:query|execute|raw)\s*\(\s*`[^`]{0,500}\$\{",
                "severity": "high",
                "description": "SQL built with a template literal",
                "category": "sql_injection",
            },
            {
                "pattern": r"\.(?:query|execute|raw)\s*\(\s*[\"'][^\"'\n]{0,500}[\"']\s*\+",
                "severity": "high",
                "description": "SQL built by string concatenation",
                "category": "sql_injection",
            },
        ],
    }

    SANDBOX_CONFIGS: dict[str, dict[str, Any]] = {
        "low": {
            "memory_limit": "256m",
            "cpu_limit": "0.5",
            "network": "none",
            "read_only": False,
        },
        "medium": {
            "memory_limit": "128m",
            "cpu_limit": "0.25",
            "network": "none",
            "read_only": True,
        },
        "high": {
            "memory_limit": "64m",
            "cpu_limit": "0.1",
            "network": "none",
            "read_only": True,
            "no_new_privileges": True,
        },
    }
