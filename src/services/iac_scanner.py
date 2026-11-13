"""IaC / Misconfiguration Scanner Service (Trivy config mode).

Real infrastructure-as-code misconfiguration engine. Where bandit/semgrep cover
*source code* and trivy/grype/osv cover *images/dependencies*, this closes the
remaining gap: Dockerfiles, Kubernetes / Helm manifests and Terraform are not
scanned at all today. `trivy config` detects insecure-by-default config (a
`USER root` Dockerfile, a privileged k8s pod, a missing resource limit, an open
Terraform security group, ...). Trivy is ALREADY installed in the image
(Dockerfile, alongside the image-CVE scanner), so this engine adds NO new CLI
and NO new dependency.

Follows the SemgrepScanner CLI-subprocess pattern: availability via
`shutil.which` (instant — never shell `--version`, whose cold start would
false-negative is_available() in-cluster) -> async subprocess -> JSON parse ->
map to `VulnerabilityMatch`. So every downstream consumer (SecurityScanResult,
the AA measureStep gate) is unchanged. Any failure (trivy absent, non-JSON,
exception) yields no matches, leaving the bandit + semgrep + regex engines
unchanged (graceful fallback) — the AA delta gate is never broken by a flaky
scan.

Scan granularity (v4): self-contained files are scanned individually (bounded +
deterministic); the two genuinely multi-file cases are scanned PER-DIRECTORY
(`trivy config <dir>`, trivy's module-aware invocation), because scanning one
file in isolation loses cross-file context and misses real misconfigs:
  * Dockerfiles — self-contained, per-file.
  * Standalone YAML k8s manifests — self-contained, per-file.
  * CloudFormation `*.json` — self-contained, per-file. A CFN template is ONE
    file (nested stacks reference siblings by S3 URL, not local paths), so it is
    NOT a multi-file case. Generic `*.json` is NOT an IaC extension (it would
    fan trivy over every package.json / tsconfig.json), so a `*.json` is scanned
    only when its content is unmistakably a CloudFormation template — detected
    by `_is_cloudformation` (top-level `AWSTemplateFormatVersion`, or a
    `Resources` map with an `AWS::`/`Custom::`/`Alexa::` resource Type). CFN
    written as YAML is already covered by the standalone-YAML path above (v4).
  * Terraform — a *directory* of files (main.tf + variables.tf + locals.tf +
    ...) whose variables/locals/modules span files (v2).
  * Helm charts — a *directory* (Chart.yaml + values.yaml + templates/*.yaml)
    whose templates are Go-templated (`{{ .Values.x }}`) and are NOT valid
    standalone manifests; scanned per-file trivy cannot render them and yields
    NOTHING. Scanning the chart-root dir lets trivy render the templates
    against values.yaml and scan the result (v3). A YAML target is mapped to
    its chart root (nearest/outermost ancestor directory with a `Chart.yaml`);
    a YAML with no chart ancestor stays a standalone per-file manifest.
  * Docker Compose — classified by NAME and parsed in-process with PyYAML. It is
    deliberately NOT handed to `trivy config`: measured with trivy v0.69.3, a
    compose file produces rc 0 with `Results` OMITTED, which is the same report
    shape as a clean scan. A compose file with `privileged: true` or a
    `/var/run/docker.sock` mount therefore read CLEAN. The in-process parser
    reports those high-risk constructs (see `_parse_compose_manifest`).
Every common IaC file-type is now covered; no file-type is excluded after v4.

Honesty: a trivy report with no `Results` is NOT proof of a clean target — the
same shape is produced for a malformed manifest and an unparsed target. It is
treated as a partial run (`ScannerPartialRunError`, engine `degraded`) only for
targets trivy always reports on: a Terraform directory, a Dockerfile with at
least one instruction, a CloudFormation template with resources, and YAML OUR
OWN parser could not parse. Parsed YAML trivy ignores (plain config,
`kustomization.yaml`, ...), Helm chart roots, empty/comment-only Dockerfiles and
CFN templates without resources stay clean: a false `degraded` is also a
failure. A `Results` entry (e.g. with `MisconfSummary` for a Terraform module
that legitimately has zero misconfigurations) remains a genuine clean.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from services.scanner_errors import (
    ScannerExecutionError,
    ScannerPartialRunError,
    load_json_report,
)
from services.security_detector import (
    ScanEngine,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)

# Trivy misconfiguration `Severity` -> VulnerabilitySeverity. Trivy config DOES
# emit CRITICAL (unlike semgrep), so it maps 1:1 and feeds the critical+high
# gate directly.
_SEVERITY_MAP: dict[str, VulnerabilitySeverity] = {
    "CRITICAL": VulnerabilitySeverity.CRITICAL,
    "HIGH": VulnerabilitySeverity.HIGH,
    "MEDIUM": VulnerabilitySeverity.MEDIUM,
    "LOW": VulnerabilitySeverity.LOW,
}

# Substrings (matched against AVDID + Title, case-insensitive) that mark a
# misconfiguration as a privilege issue -> PRIVILEGE_ESCALATION. Everything else
# maps to the INFORMATION_DISCLOSURE catch-all (the same safe default bandit /
# semgrep use for unmapped findings). Type does NOT affect the gate (it sums
# critical+high by *severity*); it only affects dedup + reporting, and IaC
# findings live in config files that the source engines never touch, so there
# is no collision either way.
_PRIVILEGE_KEYWORDS: tuple[str, ...] = (
    "privileg",  # privileged / privilege escalation
    "root",  # runs as root / USER root
    "runasnonroot",
    "capabilit",  # added linux capabilities
    "allowprivilegeescalation",
    "sys_admin",
)

# IaC file extensions trivy config recognizes by EXTENSION. Non-config YAML is a
# no-op in trivy (it only reports recognized k8s/helm/cloudformation configs), so
# passing app manifests is safe. Generic *.json is intentionally NOT an extension
# here — it would fan trivy over every package.json / tsconfig.json. CloudFormation
# JSON is instead detected by CONTENT (`_is_cloudformation`, v4), so only genuine
# CFN templates are scanned, keeping the per-file fan-out bounded.
_IAC_EXTENSIONS: frozenset[str] = frozenset({".tf", ".tofu", ".yaml", ".yml"})

# Terraform / OpenTofu extensions. These are scanned PER-DIRECTORY (not per-file)
# so trivy resolves cross-file module context (variables/locals/modules span
# main.tf + variables.tf + ...). See `scan()`.
_TERRAFORM_EXTENSIONS: frozenset[str] = frozenset({".tf", ".tofu"})

# YAML extensions. A YAML may be a standalone k8s manifest (scanned per-file) OR
# a Helm-chart template (Go-templated, scanned per chart-root dir — see
# `_find_chart_root`). The chart marker file that identifies a chart root.
_YAML_EXTENSIONS: frozenset[str] = frozenset({".yaml", ".yml"})
_HELM_CHART_MARKER: str = "Chart.yaml"
# Bound the upward Chart.yaml search so a stray YAML never walks to the
# filesystem root. Helm charts (incl. subcharts under charts/) nest shallowly.
_MAX_CHART_WALK_LEVELS: int = 8

# CloudFormation detection (v4). A `*.json` is scanned ONLY when its content is
# unmistakably a CloudFormation template — never just by extension. AWS caps a
# template at ~1 MB; bound the read so a huge non-CFN JSON blob is never fully
# parsed just to reject it.
_CFN_JSON_EXTENSION: str = ".json"
_MAX_CFN_BYTES: int = 5 * 1024 * 1024
# Resource-type prefixes that identify a CloudFormation `Resources` entry.
_CFN_RESOURCE_TYPE_PREFIXES: tuple[str, ...] = ("AWS::", "Custom::", "Alexa::")

# Docker Compose. Classified by NAME before the trivy partitioning: trivy config
# does not analyse compose files (measured v0.69.3: rc 0, `Results` omitted), so
# a compose file with `privileged: true` would otherwise report CLEAN.
# Matches `compose*.yml|yaml`, `docker-compose*.yml|yaml` and
# `<something>-compose.yml|yaml` (`compose.override.yaml`, `dev-compose.yml`)
# at any depth. The char after a prefix must be a name boundary so
# `composer.yaml` (a different thing entirely) is not swallowed.
_COMPOSE_NAME_PREFIXES: tuple[str, ...] = ("compose", "docker-compose")
_COMPOSE_SUFFIXES: tuple[str, ...] = (".yml", ".yaml")
_COMPOSE_NAME_BOUNDARIES: frozenset[str] = frozenset({"", ".", "-", "_"})
_COMPOSE_LANGUAGE: str = "docker-compose"
_COMPOSE_PATTERN_PRIVILEGED: str = "COMPOSE-PRIVILEGED"
_COMPOSE_PATTERN_DOCKER_SOCK: str = "COMPOSE-DOCKER-SOCK"
_COMPOSE_PATTERN_HOST_BIND: str = "COMPOSE-HOST-BIND"
_COMPOSE_PATTERN_NETWORK_HOST: str = "COMPOSE-NETWORK-HOST"
_COMPOSE_PATTERN_PID_HOST: str = "COMPOSE-PID-HOST"
_COMPOSE_PATTERN_CAP_ADD: str = "COMPOSE-CAP-ADD"
_DOCKER_SOCK_MARKER: str = "docker.sock"

# Bounded YAML merge resolution. Results are memoised per mapping node, so a
# 36-anchor DAG resolves in linear time; these bounds exist so a pathological
# graph can never hang the scan or raise RecursionError. Exceeding either is a
# DEGRADED partial run (ScannerPartialRunError), never a clean result and never
# a failed engine. A 36-anchor `<<: [*a, *b]` DAG needs depth <= 36 and ~70
# merge sources, so it fits comfortably inside both bounds.
_MAX_COMPOSE_MERGE_DEPTH: int = 64
_MAX_COMPOSE_MERGE_SOURCES: int = 256


class _MergeBudgetExceededError(Exception):
    """A compose file's YAML merge graph exceeds the bounded resolution budget."""


class _ComposeUnresolvableError(Exception):
    """A compose value whose effective content we cannot determine.

    Raised for unresolved variable interpolation, a value of a YAML type we
    cannot evaluate, or cross-file indirection (`extends` / `include`). The
    caller turns it into a DEGRADED partial run — UNCHECKED, never clean.
    """


# Compose variable interpolation. Only the documented simple forms are
# expanded; anything else (e.g. `${VAR:?err}`, nested defaults) is UNRESOLVED
# and degrades — never guessed.
_VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_INTERPOLATION_DEPTH: int = 8
_FALSE_SCALARS: frozenset[str] = frozenset({"false", "no", "off", "n", "0", ""})


def _parse_interpolation_expression(expression: str) -> tuple[str, str | None, str] | None:
    """Split a `${...}` body into (name, operator, default), or None if unsupported."""
    if ":-" in expression:
        name, default = expression.split(":-", 1)
        operator: str | None = ":-"
    elif "-" in expression:
        name, default = expression.split("-", 1)
        operator = "-"
    else:
        name, default, operator = expression, "", None
    if not _VAR_NAME_RE.fullmatch(name):
        return None
    return name, operator, default


def _interpolate_compose_text(text: str, env: Mapping[str, str], depth: int = 0) -> str | None:
    """Expand `$VAR`, `${VAR}`, `${VAR:-default}` and `${VAR-default}`.

    Returns None when the effective value cannot be determined: an unset
    variable with no default, a malformed/unsupported expression, or a nested
    default we cannot resolve. The caller must DEGRADE on None — an unresolvable
    value is UNCHECKED, not clean.
    """
    if depth > _MAX_INTERPOLATION_DEPTH:
        return None
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char != "$":
            out.append(char)
            index += 1
            continue
        if index + 1 < length and text[index + 1] == "$":
            out.append("$")
            index += 2
            continue
        if index + 1 < length and text[index + 1] == "{":
            end = text.find("}", index + 2)
            if end == -1:
                return None
            parsed = _parse_interpolation_expression(text[index + 2 : end])
            if parsed is None:
                return None
            name, operator, default = parsed
            value = env.get(name)
            if operator is None:
                if value is None:
                    return None
                out.append(value)
            elif operator == ":-":
                if value is None or value == "":
                    expanded = _interpolate_compose_text(default, env, depth + 1)
                    if expanded is None:
                        return None
                    out.append(expanded)
                else:
                    out.append(value)
            else:  # operator == "-"
                if value is None:
                    expanded = _interpolate_compose_text(default, env, depth + 1)
                    if expanded is None:
                        return None
                    out.append(expanded)
                else:
                    out.append(value)
            index = end + 1
            continue
        match = _VAR_NAME_RE.match(text, index + 1)
        if match is None:
            # A lone '$' is literal text: compose only expands a valid name.
            out.append("$")
            index += 1
            continue
        name = match.group(0)
        value = env.get(name)
        if value is None:
            return None
        out.append(value)
        index = match.end()
    return "".join(out)


class _MergeBudget:
    """Per-file bound on YAML merge expansion work."""

    def __init__(
        self,
        max_depth: int = _MAX_COMPOSE_MERGE_DEPTH,
        max_sources: int = _MAX_COMPOSE_MERGE_SOURCES,
    ) -> None:
        self.max_depth = max_depth
        self.max_sources = max_sources
        self.sources = 0

    def check_depth(self, depth: int) -> None:
        if depth > self.max_depth:
            raise _MergeBudgetExceededError(f"merge depth {depth} exceeds {self.max_depth}")

    def spend_source(self) -> None:
        self.sources += 1
        if self.sources > self.max_sources:
            raise _MergeBudgetExceededError(f"more than {self.max_sources} merge sources")


_DOCKER_SOCK_REMEDIATION: str = (
    "Do not mount /var/run/docker.sock; use a restricted Docker API proxy or a "
    "rootless/remote builder instead."
)


#: How deep an include/extends chain may nest before it is UNCHECKED. Compose
#: files do not chain deeply in practice; the cap exists so a crafted or
#: accidental cycle cannot make the scanner walk unbounded paths.
_MAX_COMPOSE_INDIRECTION_DEPTH = 10


def _compose_scan_root(file_paths: Sequence[str | Path]) -> str:
    """The workspace root a compose include may not leave.

    The scanner is given the repository's IaC files; their common directory is
    the workspace. A reference resolving above it (``../../etc/passwd``) is
    outside what this scan can vouch for and stays UNCHECKED.
    """
    dirs = [os.path.dirname(os.path.abspath(str(p))) for p in file_paths]
    if not dirs:
        return os.path.abspath(os.sep)
    try:
        return os.path.commonpath(dirs)
    except ValueError:
        return dirs[0]


def _resolve_compose_ref(raw: str, base_file: str, scan_root: str) -> str:
    """Resolve one include/extends reference to a readable file in the workspace.

    A remote reference (URL), a path that leaves the scanned workspace, and a
    missing file are all UNCHECKED: raise ``_ComposeUnresolvableError``.
    """
    ref = raw.strip()
    if not ref:
        raise _ComposeUnresolvableError("an empty include/extends path")
    if "://" in ref or ref.startswith("git@"):
        raise _ComposeUnresolvableError(f"remote reference {ref!r} is not resolved")
    candidate = ref if os.path.isabs(ref) else os.path.join(os.path.dirname(base_file), ref)
    resolved = os.path.normpath(os.path.abspath(candidate))
    root = os.path.normpath(os.path.abspath(scan_root))
    try:
        inside = os.path.commonpath([root, resolved]) == root
    except ValueError:
        inside = False
    if not inside:
        raise _ComposeUnresolvableError(f"{ref!r} resolves outside the scanned workspace")
    if not os.path.isfile(resolved):
        raise _ComposeUnresolvableError(f"{ref!r} does not exist")
    return resolved


def _compose_include_refs(
    node: Node,
    cache: dict[int, list[tuple[Node, Node]]] | None,
    budget: _MergeBudget | None,
) -> list[str]:
    """The path references in an ``include:`` value.

    Compose accepts a path string, a list of them, a mapping with ``path``, or
    a mapping whose ``path`` is itself a list (openplanner's compose.yaml:
    ``include: [{path: [docker-compose.yml, dev/compose.dev.yml]}]``). Other
    mapping keys (env_file, project_directory) do not name files this scanner
    reads. Any other shape is UNCHECKED.
    """
    if isinstance(node, ScalarNode):
        text = _scalar_text(node)
        return [text] if text else []
    if isinstance(node, MappingNode):
        path_node = _mapping_lookup(node, "path", cache=cache, budget=budget)
        if isinstance(path_node, ScalarNode):
            text = _scalar_text(path_node)
            if not text:
                raise _ComposeUnresolvableError("an 'include' mapping with an empty 'path'")
            return [text]
        if isinstance(path_node, SequenceNode):
            # One level only: a list of scalars. Anything deeper is not a
            # compose construct we can interpret (and a self-referential alias
            # must not recurse forever).
            refs: list[str] = []
            for item in path_node.value:
                text = _scalar_text(item)
                if not text:
                    raise _ComposeUnresolvableError(
                        "an 'include' path list contains a non-scalar entry"
                    )
                refs.append(text)
            return refs
        raise _ComposeUnresolvableError("an 'include' mapping without a usable 'path'")
    if isinstance(node, SequenceNode):
        refs: list[str] = []
        for item in node.value:
            refs.extend(_compose_include_refs(item, cache, budget))
        return refs
    raise _ComposeUnresolvableError(f"'include' has a {type(node).__name__} value")


def _compose_indirection_refs(
    root: MappingNode,
    *,
    cache: dict[int, list[tuple[Node, Node]]] | None = None,
    budget: _MergeBudget | None = None,
) -> list[str]:
    """Every cross-file reference in a compose document (raw, unresolved).

    Root ``include`` entries plus service-level ``extends.file`` values. A bare
    ``extends: <service-name>`` refers to a service in the same file and is
    ignored (the per-service checks already cover every service defined here).
    """
    root_extends = _mapping_lookup(root, "extends", cache=cache, budget=budget)
    if root_extends is not None:
        # `extends` is a service-level key; at the document root it is not a
        # construct compose defines, so its effective content is unknowable.
        raise _ComposeUnresolvableError("the document root uses 'extends' indirection")
    refs: list[str] = []
    include_node = _mapping_lookup(root, "include", cache=cache, budget=budget)
    if include_node is not None:
        refs.extend(_compose_include_refs(include_node, cache, budget))
    services = _mapping_lookup(root, "services", cache=cache, budget=budget)
    if isinstance(services, MappingNode):
        for _, service_node in _mapping_entries(services, cache=cache, budget=budget):
            if not isinstance(service_node, MappingNode):
                continue
            extends = _mapping_lookup(service_node, "extends", cache=cache, budget=budget)
            if not isinstance(extends, MappingNode):
                continue
            file_node = _mapping_lookup(extends, "file", cache=cache, budget=budget)
            text = _scalar_text(file_node)
            if text:
                refs.append(text)
    return refs


def _is_compose_file(path: str) -> bool:
    """True for a Docker Compose manifest (`compose*.yml|yaml`,
    `docker-compose*.yml|yaml`, `<something>-compose.yml|yaml`), at any directory
    depth. Compose files are always named, never arbitrary YAML, so this is a
    NAME check — done before trivy, which cannot scan them. `composer.yaml` and
    `composer.json` are NOT compose files."""
    name = Path(path).name.lower()
    if not name.endswith(_COMPOSE_SUFFIXES):
        return False
    if Path(name).stem.endswith("-compose"):
        return True
    for prefix in _COMPOSE_NAME_PREFIXES:
        if name.startswith(prefix):
            boundary = name[len(prefix) : len(prefix) + 1]
            return boundary in _COMPOSE_NAME_BOUNDARIES
    return False


def _is_dockerfile(path: str) -> bool:
    """True for Dockerfile / Containerfile / *.dockerfile (scanned per-file)."""
    name = Path(path).name.lower()
    return name in ("dockerfile", "containerfile") or name.endswith(".dockerfile")


# YAML 1.1 scalar spellings PyYAML resolves to a boolean true. `privileged: true`
# is the documented form; the rest are accepted.
_TRUE_SCALARS: frozenset[str] = frozenset({"true", "yes", "on", "y"})


def _compose_scalar_value(node: Node, env: Mapping[str, str], *, key: str, service: str) -> str:
    """The interpolation-expanded text of a service-level scalar value.

    Raises ``_ComposeUnresolvableError`` when the node is not a scalar or its
    value cannot be determined — never returns a guessed value.
    """
    if not isinstance(node, ScalarNode):
        raise _ComposeUnresolvableError(
            f"service {service!r}.{key} is a {type(node).__name__}, not a scalar value"
        )
    resolved = _interpolate_compose_text(str(node.value), env)
    if resolved is None:
        raise _ComposeUnresolvableError(
            f"unresolved interpolation in service {service!r}.{key}: {node.value!r}"
        )
    return resolved


def _compose_bool_value(node: Node, env: Mapping[str, str], *, key: str, service: str) -> bool:
    """Evaluate a service-level boolean after interpolation.

    `privileged: ${PRIV:-true}` is a STRING scalar in YAML, so the tag cannot be
    trusted; the effective text decides. A text that is neither a true nor a
    false spelling is UNRESOLVED (degrade), never assumed false.
    """
    text = _compose_scalar_value(node, env, key=key, service=service).strip().lower()
    if text in _TRUE_SCALARS:
        return True
    if text in _FALSE_SCALARS:
        return False
    raise _ComposeUnresolvableError(
        f"service {service!r}.{key} resolves to {text!r}, which is not a boolean"
    )


def _compose_capabilities(
    node: Node, env: Mapping[str, str], *, service: str
) -> list[tuple[str, Node]]:
    """Interpolation-expanded (capability, node) pairs from a service `cap_add`."""
    if isinstance(node, ScalarNode):
        items: list[Node] = [node]
    elif isinstance(node, SequenceNode):
        items = node.value
    else:
        raise _ComposeUnresolvableError(
            f"service {service!r}.cap_add is a {type(node).__name__}, not a capability list"
        )
    capabilities: list[tuple[str, Node]] = []
    for item in items:
        text = _compose_scalar_value(item, env, key="cap_add", service=service)
        capabilities.append((text.strip().upper(), item))
    return capabilities


def _compose_volume_source(value: str) -> str | None:
    """The source half of a short-syntax volume (`src:dst[:mode]`), or None.

    A compose volume with no `:` is a container-only path / named volume — it
    does not name a host path, so it can never be a host bind.
    """
    if ":" not in value:
        return None
    return value.split(":", 1)[0].strip()


def _scalar_text(node: Node | None) -> str | None:
    """The text of a scalar YAML node, or None for a missing/mapping/sequence node."""
    return str(node.value) if isinstance(node, ScalarNode) else None


def _merge_sources(node: Node) -> list[MappingNode]:
    """The mapping(s) a YAML `<<` merge key pulls entries from.

    PyYAML resolves aliases at COMPOSE time (an alias IS the anchored node, not
    a distinct AliasNode), so `<<: *anchor` arrives here as a MappingNode and
    `<<: [*a, *b]` as a SequenceNode of them.
    """
    if isinstance(node, MappingNode):
        return [node]
    if isinstance(node, SequenceNode):
        return [item for item in node.value if isinstance(item, MappingNode)]
    return []


def _mapping_entries(
    node: MappingNode,
    stack: frozenset[int] = frozenset(),
    *,
    cache: dict[int, list[tuple[Node, Node]]] | None = None,
    budget: _MergeBudget | None = None,
) -> list[tuple[Node, Node]]:
    """Effective (key, value) pairs of a mapping with `<<` merge keys resolved.

    Matches docker compose / YAML merge semantics: explicit keys override merged
    keys, and for `<<: [*a, *b]` the EARLIER mapping wins over the later one. A
    self-referential merge is ignored rather than recursing forever.

    Results are memoised per mapping node (`cache`, keyed by node identity), so
    a DAG with many incoming merges is resolved once per anchor instead of
    exponentially. `budget` bounds the depth and total merge sources; exceeding
    it raises ``_MergeBudgetExceededError``, which the caller turns into a DEGRADED
    partial run.

    The returned nodes are the ones from the anchor definition, so a merged
    finding keeps the line where the risky value is actually written.
    """
    node_id = id(node)
    if node_id in stack:
        return []
    if cache is not None and node_id in cache:
        return cache[node_id]
    if budget is not None:
        budget.check_depth(len(stack))
    stack = stack | {node_id}
    merged: dict[str, tuple[Node, Node]] = {}
    explicit: list[tuple[Node, Node]] = []
    explicit_names: set[str] = set()
    for key_node, value_node in node.value:
        name = _scalar_text(key_node)
        if name == "<<":
            for source in _merge_sources(value_node):
                # Spend only on real expansion work: a memoised anchor is O(1)
                # to reuse, so many services merging the same one stay cheap.
                if budget is not None and (cache is None or id(source) not in cache):
                    budget.spend_source()
                for source_key, source_value in _mapping_entries(
                    source, stack, cache=cache, budget=budget
                ):
                    source_name = _scalar_text(source_key)
                    if source_name is not None and source_name not in merged:
                        merged[source_name] = (source_key, source_value)
        elif name is not None:
            explicit.append((key_node, value_node))
            explicit_names.add(name)
    entries = [(k, v) for name, (k, v) in merged.items() if name not in explicit_names]
    entries.extend(explicit)
    if cache is not None:
        cache[node_id] = entries
    return entries


def _mapping_lookup(
    node: MappingNode,
    key: str,
    *,
    cache: dict[int, list[tuple[Node, Node]]] | None = None,
    budget: _MergeBudget | None = None,
) -> Node | None:
    """The effective value node for `key`, with `<<` merge keys resolved."""
    for key_node, value_node in _mapping_entries(node, cache=cache, budget=budget):
        if _scalar_text(key_node) == key:
            return value_node
    return None


def _yaml_parse_fails(path: str) -> bool:
    """The ONLY YAML honesty trigger: OUR OWN PyYAML parse failed.

    YAML is deliberately NOT in the honesty gate by kind. Measured with trivy
    v0.69.3: a `kustomization.yaml` (and any other parsed YAML trivy ignores)
    yields rc 0 with no `Results`; degrading that would be a permanent false
    `degraded` on every kustomize repo. A file WE cannot parse is different —
    malformed IaC must never read clean.

    Fail-closed on a read error (True): an unreadable file cannot be proven
    benign.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True
    try:
        # compose_all is lazy; force it so parse errors surface here.
        list(yaml.compose_all(text))
    except yaml.YAMLError:
        return True
    return False


def _dockerfile_has_instructions(path: str) -> bool:
    """True when a Dockerfile has at least one non-comment, non-blank line.

    An empty or comment-only Dockerfile legitimately yields no trivy Results, so
    it must not degrade. A read error is fail-closed (True).
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return True
    return False


def _cfn_json_has_resources(path: str) -> bool:
    """True when a CloudFormation JSON template has a non-empty `Resources` map.

    A template carrying only `AWSTemplateFormatVersion` (no resources)
    legitimately yields no trivy Results and must not degrade. Fail-closed on a
    read/parse error (True).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return True
    if not isinstance(data, dict):
        return False
    resources = data.get("Resources")
    return isinstance(resources, dict) and bool(resources)


def _dir_expects_results(directory: str) -> bool:
    """Only a Terraform module directory is expected to produce Results.

    trivy always emits Results for a `.tf` set. A Helm chart root may
    legitimately render nothing (an empty chart, or every template inside a
    false `{{- if .Values.enabled }}`), so it is skipped by the gate. An
    unlistable directory is fail-closed (True).
    """
    try:
        entries = list(Path(directory).iterdir())
    except OSError:
        return True
    return any(entry.suffix.lower() in _TERRAFORM_EXTENSIONS for entry in entries)


def _target_expects_results(target: str, base_dir: str | None) -> bool:
    """True when `trivy config` is expected to report `Results` for the target.

    The rule is deliberately narrow — a false `degraded` is also a failure:
      * Terraform directories — trivy always emits Results for a `.tf` set.
      * Dockerfiles with at least one instruction.
      * CloudFormation JSON with a non-empty `Resources` map.
      * YAML only when OUR own parse of it FAILS (malformed IaC).
    Helm chart roots, empty/comment-only Dockerfiles, empty CFN templates,
    kustomization/plain YAML and any parsed YAML trivy ignores are skipped.
    An unknown or empty target is fail-closed (True).
    """
    if base_dir is not None:
        return _dir_expects_results(base_dir)
    if not target:
        return True
    if _is_dockerfile(target):
        return _dockerfile_has_instructions(target)
    if _is_terraform(target):
        return True
    suffix = Path(target).suffix.lower()
    if suffix == _CFN_JSON_EXTENSION:
        return _cfn_json_has_resources(target)
    if suffix in _YAML_EXTENSIONS:
        return _yaml_parse_fails(target)
    return False


def _is_cloudformation(path: str) -> bool:
    """Return True iff `path` is a `*.json` whose content is a CloudFormation
    template. CFN templates are single self-contained files, so they are scanned
    per-file (the Dockerfile / standalone-YAML bucket), not per-directory.

    A JSON object is treated as CFN iff it carries a top-level
    `AWSTemplateFormatVersion`, OR a non-empty `Resources` map with at least one
    resource whose `Type` is an `AWS::`/`Custom::`/`Alexa::` string. This rejects
    package.json / tsconfig.json / lockfiles (no such markers). Filesystem- and
    content-dependent by necessity (only `scan()`'s partition calls it; the JSON
    parser stays filesystem-pure for canned-JSON unit tests). Any read/parse
    failure → False (graceful — never breaks the scan)."""
    if Path(path).suffix.lower() != _CFN_JSON_EXTENSION:
        return False
    try:
        if Path(path).stat().st_size > _MAX_CFN_BYTES:
            return False
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    if "AWSTemplateFormatVersion" in data:
        return True
    resources = data.get("Resources")
    if isinstance(resources, dict) and resources:
        for resource in resources.values():
            if not isinstance(resource, dict):
                continue
            rtype = resource.get("Type")
            if isinstance(rtype, str) and rtype.startswith(_CFN_RESOURCE_TYPE_PREFIXES):
                return True
    return False


def _find_chart_root(path: str, max_levels: int = _MAX_CHART_WALK_LEVELS) -> str | None:
    """Return the Helm chart-root directory a YAML belongs to, or None.

    A chart root is a directory containing a `Chart.yaml`. Walking up from the
    file, we return the OUTERMOST ancestor that has one (within max_levels) so
    an umbrella chart is scanned ONCE — its rendering covers nested subcharts
    (`charts/<sub>/Chart.yaml`), avoiding a parent+subchart double-scan. Bounded
    so a stray YAML never ascends to the filesystem root. Filesystem-dependent
    by necessity (only `scan()`'s partition calls it; the JSON parser stays
    filesystem-pure for canned-JSON unit tests)."""
    chart_root: str | None = None
    current = Path(path).parent
    for _ in range(max_levels):
        try:
            if (current / _HELM_CHART_MARKER).is_file():
                chart_root = str(current)  # keep climbing — prefer outermost
        except OSError:  # pragma: no cover - defensive (perms / broken path)
            break
        parent = current.parent
        if parent == current:  # reached filesystem root
            break
        current = parent
    return chart_root


def _is_iac_file(path: str) -> bool:
    """True for files this scanner acts on: Dockerfile/Containerfile,
    *.dockerfile, Terraform, and YAML manifests (including compose files,
    which are parsed in-process rather than by trivy)."""
    return _is_dockerfile(path) or Path(path).suffix.lower() in _IAC_EXTENSIONS


def is_iac_scan_candidate(path: str) -> bool:
    """True if `path` is a file this scanner would act on — an IaC manifest
    (Dockerfile/Containerfile/Terraform/YAML) or a content-sniffed
    CloudFormation ``*.json``.

    Public so the container file-path resolver can feed IaC files into the
    whole-codebase scan. Without it the resolver collects only source-code
    extensions, so the IaC engine receives zero IaC files and is silently inert
    in the primary ``scanContainerSecurity`` path (it only ever ran in unit
    tests + the unused unified scanner). Kept in lock-step with ``scan()`` by
    delegating to the exact same predicates ``scan()`` uses.
    """
    return _is_iac_file(path) or _is_cloudformation(path)


def _is_terraform(path: str) -> bool:
    """True for Terraform / OpenTofu files (scanned per-directory as a module)."""
    return Path(path).suffix.lower() in _TERRAFORM_EXTENSIONS


def _is_yaml(path: str) -> bool:
    """True for YAML files (a standalone k8s manifest OR a Helm-chart template)."""
    return Path(path).suffix.lower() in _YAML_EXTENSIONS


def _file_kind(path: str) -> str:
    if _is_dockerfile(path):
        return "dockerfile"
    suffix = Path(path).suffix.lower()
    if suffix in (".tf", ".tofu"):
        return "terraform"
    if suffix in (".yaml", ".yml"):
        return "kubernetes"
    # Only content-sniffed CloudFormation templates reach the per-file scan with
    # a .json suffix (generic *.json is never an IaC target), so .json -> CFN.
    if suffix == ".json":
        return "cloudformation"
    return "unknown"


# `trivy config` exit codes (Dockerfile pins trivy v0.69.3; measured): scan()
# does NOT pass `--exit-code`, so findings do NOT change the exit code — a
# Dockerfile with 4 FAIL misconfigurations exits 0; a fatal error (e.g. missing
# target) exits 1 with empty stdout. Only 0 is success.
_OK_EXIT_CODES = frozenset({0})

# `trivy config --format json` report shape (v0.69.3, measured): an object that
# ALWAYS has "SchemaVersion": 2, "Trivy", "ReportID", "CreatedAt",
# "ArtifactName", "ArtifactType"; "Results" is OMITTED when no config file was
# analysed, else a list of
# {"Target", "Class": "config", "Type", "MisconfSummary": {"Successes",
# "Failures"}, "Misconfigurations": [{"AVDID", "Status": "FAIL"|"PASS"|..}]}.
# trivy's JSON exposes NO partial-run / per-target error field: measured, a
# malformed manifest yields no Results and a syntactically broken .tf is
# reported as all-Successes, both exit 0. A missing Results is therefore
# ambiguous; it is a partial run (`ScannerPartialRunError` -> engine `degraded`)
# only for the narrow target classes in `_target_expects_results`. A per-target
# failure with findings from other targets in hand is also `degraded`.
_REQUIRED_KEYS: dict[str, type] = {"SchemaVersion": int}


class IaCScanner:
    """Scanner for infrastructure-as-code misconfigurations using `trivy config`."""

    def __init__(self) -> None:
        # Presence probe via shutil.which — instant and reliable. Do NOT shell
        # `trivy --version` here (the E3.8 lesson): a slow CLI cold start would
        # false-negative is_available() and leave the engine inert in the
        # request path.
        self.trivy_available = self._check_available()

    def _check_available(self) -> bool:
        return shutil.which("trivy") is not None

    def is_available(self) -> bool:
        return self.trivy_available

    async def scan(
        self, file_paths: Sequence[str | Path], timeout: int = 180
    ) -> list[VulnerabilityMatch]:
        """Run `trivy config` over the IaC files in file_paths and return mapped
        matches.

        Non-IaC files are filtered out. Dockerfiles and standalone YAML
        manifests are self-contained, so each unique file is scanned
        individually (bounded + deterministic — no recursive whole-repo
        blow-up). The two multi-file cases are scanned PER-DIRECTORY (`trivy
        config <dir>`) so cross-file context resolves, each scanned ONCE: a
        Terraform module (N .tf files) by its parent dir; a Helm chart (Go-
        templated `templates/*.yaml`) by its chart-root dir (so trivy renders
        the templates against values.yaml — per-file it cannot and finds
        nothing). Docker Compose files are classified by NAME first and parsed
        in-process, never handed to trivy (which does not analyse them and
        returns the same empty report as a clean scan). Without ``--exit-code``
        trivy exits 0 with findings, so any non-zero exit, any stdout that is
        not a trivy report, and any target trivy always reports on whose report
        carries no ``Results`` fails that target (``ScannerExecutionError`` /
        ``ScannerPartialRunError``, carrying the other targets' findings).
        """
        if not self.trivy_available:
            logger.warning("trivy not available for IaC scanning")
            return []

        # Partition IaC targets: Dockerfile + standalone YAML + CloudFormation
        # JSON scanned per-file (self-contained); Terraform scanned per parent-dir
        # (module-aware); Helm-chart YAML scanned per chart-root dir (rendered).
        # All deduped, order-preserving.
        seen_files: set[str] = set()
        file_targets: list[str] = []
        seen_tf_dirs: set[str] = set()
        tf_dirs: list[str] = []
        seen_helm_dirs: set[str] = set()
        helm_dirs: list[str] = []
        seen_compose: set[str] = set()
        compose_targets: list[str] = []
        for p in file_paths:
            sp = str(p)
            # Compose classification comes FIRST and is by NAME, and it WINS
            # over Helm-chart mapping. trivy config cannot analyse a compose
            # file (measured: rc 0, `Results` omitted, i.e. identical to a
            # clean report), so it must never enter the trivy target list — it
            # is parsed in-process instead. A repo-root Chart.yaml must not
            # stop `dev/docker-compose.yml` from being parsed (measured: that
            # made a privileged compose file read CLEAN).
            if _is_compose_file(sp):
                if sp not in seen_compose:
                    seen_compose.add(sp)
                    compose_targets.append(sp)
                continue
            # `_is_iac_file` matches by extension/name; CloudFormation JSON is
            # matched by CONTENT (a *.json is otherwise not an IaC extension).
            if not _is_iac_file(sp) and not _is_cloudformation(sp):
                continue
            if _is_terraform(sp):
                d = str(Path(sp).parent) or "."
                if d not in seen_tf_dirs:
                    seen_tf_dirs.add(d)
                    tf_dirs.append(d)
                continue
            # A YAML may belong to a Helm chart (Go-templated → must be rendered
            # at the chart root) or be a standalone manifest (per-file).
            if _is_yaml(sp):
                chart_root = _find_chart_root(sp)
                if chart_root is not None:
                    if chart_root not in seen_helm_dirs:
                        seen_helm_dirs.add(chart_root)
                        helm_dirs.append(chart_root)
                    continue
            if sp not in seen_files:
                seen_files.add(sp)
                file_targets.append(sp)

        # Expand cross-file compose indirection (root `include`, service
        # `extends.file`) into the same compose-scan set: each resolved file is
        # scanned once, like any other compose target, so the included services
        # are actually checked. Remote, out-of-workspace, missing, cyclic and
        # over-deep references stay UNCHECKED (the engine degrades).
        compose_problems: list[str] = []
        compose_resolved_ok: dict[str, bool] = {}

        def _compose_key(path: str) -> str:
            return os.path.normpath(os.path.abspath(path))

        if compose_targets:
            compose_scan_root = _compose_scan_root(file_paths)
            queued = {_compose_key(path) for path in compose_targets}

            def _expand(path: str, ancestry: tuple[str, ...]) -> None:
                key = _compose_key(path)
                compose_resolved_ok.setdefault(key, True)
                try:
                    root_node = yaml.compose(Path(path).read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError):
                    # The parse step reports this file's read/YAML failure.
                    return
                if not isinstance(root_node, MappingNode):
                    return
                try:
                    refs = _compose_indirection_refs(root_node)
                except (_ComposeUnresolvableError, _MergeBudgetExceededError) as e:
                    compose_problems.append(f"{path}: {e}")
                    compose_resolved_ok[key] = False
                    return
                for raw in refs:
                    if len(ancestry) >= _MAX_COMPOSE_INDIRECTION_DEPTH:
                        compose_problems.append(
                            f"{path}: include/extends chain deeper than "
                            f"{_MAX_COMPOSE_INDIRECTION_DEPTH}"
                        )
                        compose_resolved_ok[key] = False
                        continue
                    try:
                        resolved = _resolve_compose_ref(raw, path, compose_scan_root)
                    except _ComposeUnresolvableError as e:
                        compose_problems.append(f"{path}: {e}")
                        compose_resolved_ok[key] = False
                        continue
                    if resolved in ancestry:
                        compose_problems.append(f"{path}: include/extends cycle via {raw!r}")
                        compose_resolved_ok[key] = False
                        continue
                    if resolved in queued:
                        continue  # diamond reference: the file is scanned once
                    queued.add(resolved)
                    compose_targets.append(resolved)
                    _expand(resolved, (*ancestry, resolved))

            for compose in list(compose_targets):
                _expand(compose, (_compose_key(compose),))

        if not file_targets and not tf_dirs and not helm_dirs and not compose_targets:
            return []

        matches: list[VulnerabilityMatch] = []
        # One `trivy config` invocation per target. A failure on ONE target must
        # neither be swallowed (reporting the rest as a complete clean scan) nor
        # abort the others (discarding real findings we already have). So: keep
        # scanning, remember the first failure, and re-raise it at the end
        # carrying every finding collected — degraded WITH results.
        first_error: ScannerExecutionError | None = None

        async def _collect(target: str, base_dir: str | None = None) -> None:
            nonlocal first_error
            try:
                matches.extend(await self._scan_one(target, timeout, base_dir=base_dir))
            except ScannerExecutionError as exc:
                logger.error(f"trivy config failed on {target}: {exc}")
                if first_error is None:
                    first_error = exc

        for target in file_targets:
            await _collect(target)
        # Directory mode (Terraform module + Helm chart root): base_dir resolves
        # trivy's directory-relative Result.Target paths back to absolute,
        # consistent with the source engines.
        for directory in (*tf_dirs, *helm_dirs):
            await _collect(directory, base_dir=directory)
        # Compose is parsed in-process (trivy cannot analyse it). A malformed
        # compose file is a partial run — never a silently skipped file.
        for compose in compose_targets:
            try:
                matches.extend(
                    self._scan_compose(
                        compose,
                        indirections_resolved=compose_resolved_ok.get(_compose_key(compose), False),
                    )
                )
            except ScannerExecutionError as exc:
                logger.error(f"docker-compose parse failed on {compose}: {exc}")
                # A compose file that stops mid-walk (merge budget / recursion)
                # keeps the findings it already produced; they ride along with
                # the other files' findings in `partial_findings`.
                if exc.partial_findings:
                    matches.extend(exc.partial_findings)
                if first_error is None:
                    first_error = exc

        if compose_problems:
            problem = "; ".join(compose_problems[:5])
            if len(compose_problems) > 5:
                problem += f" (+{len(compose_problems) - 5} more)"
            logger.error("docker-compose indirection unresolved: %s", problem)
            if first_error is None:
                first_error = ScannerPartialRunError(
                    "trivy-iac",
                    0,
                    problem,
                    reason=f"docker-compose include/extends unresolved: {problem}",
                )

        if first_error is not None:
            first_error.partial_findings = matches
            raise first_error
        return matches

    async def _scan_one(
        self, target: str, timeout: int, base_dir: str | None = None
    ) -> list[VulnerabilityMatch]:
        try:
            cmd = [
                "trivy",
                "config",
                "--format",
                "json",
                "--quiet",
                target,
            ]
            logger.debug(f"Running trivy config on {target}")
            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout)
            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"trivy config stderr: {stderr_text}")
            # Unexpected exit code, empty / non-JSON / null / wrong-shape stdout
            # -> ScannerExecutionError: this target was not scanned. Reporting []
            # would present an unscanned Dockerfile as misconfig-free.
            data = load_json_report(
                "trivy-iac",
                returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr_text,
                ok_exit_codes=_OK_EXIT_CODES,
                required=_REQUIRED_KEYS,
            )
            results = data.get("Results")
            if results is not None and not isinstance(results, list):
                raise ScannerExecutionError(
                    "trivy-iac",
                    returncode,
                    stderr_text,
                    reason="report has a non-list 'Results' (wrong-shape output)",
                )
            return self._map_trivy_config_report(data, fallback_path=target, base_dir=base_dir)
        except ScannerExecutionError:
            raise
        except TimeoutError as e:
            logger.error(f"trivy config timed out after {timeout}s on {target}")
            raise ScannerExecutionError("trivy-iac", -1, "timed out") from e
        except Exception as e:
            logger.error(f"Error running trivy config on {target}: {e}")
            # An engine that could not run must surface as failed (R215/R216),
            # never as an ok engine with zero findings.
            raise ScannerExecutionError("trivy-iac", -1, f"{type(e).__name__}: {e}") from e

    def _parse_trivy_config_json(
        self, output: str, fallback_path: str = "", base_dir: str | None = None
    ) -> list[VulnerabilityMatch]:
        """Parse `trivy config` JSON: {"Results": [{"Target", "Misconfigurations": [...]}]}.

        Only `Status == "FAIL"` misconfigurations are real findings — trivy also
        lists PASS checks, which must be filtered out so the gate is never
        inflated by passing checks.

        When the scan argument was a directory (Terraform module mode), trivy
        reports each `Result.Target` relative to that directory — `base_dir`
        resolves those back to absolute paths so finding `file_path`s stay
        consistent with the source engines (which use absolute workspace paths).

        When the scan argument was a single FILE (Dockerfile / standalone
        manifest), `fallback_path` is the file trivy was actually given and is
        authoritative for relative `Target`s — see `_resolve_result_target`.
        """
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError) as e:
            raise ScannerExecutionError(
                "trivy-iac", 0, reason="produced output that is not JSON"
            ) from e
        if not isinstance(data, dict):
            raise ScannerExecutionError(
                "trivy-iac",
                0,
                reason=f"produced JSON {type(data).__name__} instead of a report object",
            )
        return self._map_trivy_config_report(data, fallback_path, base_dir)

    def _map_trivy_config_report(
        self, data: dict, fallback_path: str = "", base_dir: str | None = None
    ) -> list[VulnerabilityMatch]:
        results = data.get("Results")
        if not results and _target_expects_results(fallback_path, base_dir):
            # No `Results` is NOT a clean scan. Measured with trivy v0.69.3:
            # a malformed manifest exits 0 with `Results` omitted,
            # indistinguishable from a clean report. Degrade — but only for the
            # narrow target classes `_target_expects_results` says trivy always
            # reports on; parsed YAML trivy ignores, Helm chart roots, empty
            # Dockerfiles and empty CFN templates are skipped before this check
            # (a false `degraded` is also a failure).
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                reason=(
                    f"report has no 'Results' for "
                    f"{fallback_path or base_dir or 'the scanned target'!r} — "
                    "trivy returned a report but did not analyse a target it is "
                    "expected to scan"
                ),
            )
        matches: list[VulnerabilityMatch] = []
        for result in results or []:
            if not isinstance(result, dict):
                continue
            target = self._resolve_result_target(result.get("Target"), fallback_path, base_dir)
            for mc in result.get("Misconfigurations", []) or []:
                if not isinstance(mc, dict):
                    continue
                if str(mc.get("Status", "")).upper() == "PASS":
                    continue
                try:
                    matches.append(self._to_match(mc, target))
                except Exception as e:  # pragma: no cover - defensive
                    logger.debug(f"Failed to map trivy misconfiguration: {e}")

        return matches

    @staticmethod
    def _resolve_result_target(reported: object, fallback_path: str, base_dir: str | None) -> str:
        """Map a trivy `Result.Target` back to the path that was really scanned.

        FILE mode (``base_dir is None``): trivy was invoked on exactly one
        file, and ``fallback_path`` IS that file, so it wins for any relative
        ``Target``. trivy computes a relative Target against its own working
        directory and may emit a `../` chain that names no real file — measured
        live 2026-11-05: ``../../../../app/Dockerfile`` for a Dockerfile that
        lives at ``<repo>/dev/check/Dockerfile`` (the report then blamed a path
        that does not exist). An ABSOLUTE Target is trivy's own resolution and
        is kept. A relative Target is kept only when there is no fallback at
        all (direct parser use without a known scanned path).

        DIRECTORY mode (Terraform module / Helm chart root): trivy emits
        ``Target`` relative to ``base_dir``, so a relative Target is joined to
        it; an absolute Target is kept as-is.
        """
        target = str(reported) if reported else ""
        if base_dir:
            if target and not Path(target).is_absolute():
                return str(Path(base_dir) / target)
            return target or fallback_path
        if target and Path(target).is_absolute():
            return target
        return fallback_path or target

    def _to_match(self, mc: dict, target: str) -> VulnerabilityMatch:
        avd_id = str(mc.get("AVDID") or mc.get("ID") or "")
        title = str(mc.get("Title") or avd_id or "misconfiguration")
        description = str(mc.get("Message") or mc.get("Description") or "")
        severity = _SEVERITY_MAP.get(
            str(mc.get("Severity", "")).upper(), VulnerabilitySeverity.MEDIUM
        )

        cause = mc.get("CauseMetadata") or {}
        # trivy omits CauseMetadata.StartLine for checks that are not anchored
        # to a line — e.g. DS-0002 ("no USER directive") is a WHOLE-FILE
        # finding. 0 is the honest representation of "trivy supplied no line",
        # matching the existing `finding_filters` convention that clamps a
        # non-positive line to 1 before reading source. It is NOT line 0 of
        # the file and consumers must not render it as one. We deliberately do
        # not synthesise an anchor (e.g. the file's last line): for a missing
        # directive every line is equally uninvolved, and in directory mode
        # `target` may name a whole module with no single file to count.
        line_start = int(cause.get("StartLine", 0) or 0)
        line_end = int(cause.get("EndLine", line_start) or line_start)
        code = cause.get("Code") or {}
        snippet = "\n".join(
            str(line.get("Content", ""))
            for line in (code.get("Lines") or [])
            if isinstance(line, dict)
        ).strip()

        references = self._as_str_list(mc.get("References"))
        primary_url = mc.get("PrimaryURL")
        if primary_url and str(primary_url) not in references:
            references.insert(0, str(primary_url))

        return VulnerabilityMatch(
            engine=ScanEngine.TRIVY_IAC,
            id=f"trivy_config_{avd_id}_{target}_{line_start}",
            vulnerability_type=self._classify_type(avd_id, title),
            severity=severity,
            # trivy config is rule-deterministic (not a heuristic), so findings
            # are high-confidence.
            confidence=VulnerabilityConfidence.HIGH,
            file_path=target,
            language=_file_kind(target),
            line_start=line_start,
            line_end=line_end,
            pattern_id=avd_id,
            title=title,
            description=description,
            code_snippet=snippet,
            remediation_advice=str(mc.get("Resolution", "")),
            references=references,
            matched_patterns=[avd_id] if avd_id else [],
        )

    @staticmethod
    def _classify_type(avd_id: str, title: str) -> VulnerabilityType:
        haystack = f"{avd_id} {title}".lower()
        if any(kw in haystack for kw in _PRIVILEGE_KEYWORDS):
            return VulnerabilityType.PRIVILEGE_ESCALATION
        return VulnerabilityType.INFORMATION_DISCLOSURE

    def _scan_compose(
        self, target: str, *, indirections_resolved: bool = False
    ) -> list[VulnerabilityMatch]:
        """Parse one docker-compose file in-process.

        A file that cannot be read or parsed raises ``ScannerPartialRunError``:
        the engine degrades, and the file is never silently skipped (which
        would report a malformed compose file as clean).

        ``indirections_resolved`` is set by ``scan()`` once every include /
        extends-file reference of this file has been resolved and added to the
        compose scan set. A direct caller (tests, other code) leaves it False,
        so cross-file indirection there is still reported UNCHECKED.
        """
        try:
            text = Path(target).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                reason=(f"docker-compose file {target} could not be read ({type(e).__name__})"),
            ) from e
        return self._parse_compose_manifest(
            text, target, indirections_resolved=indirections_resolved
        )

    def _parse_compose_manifest(
        self,
        text: str,
        target: str,
        env: Mapping[str, str] | None = None,
        *,
        indirections_resolved: bool = False,
    ) -> list[VulnerabilityMatch]:
        """Report the high-risk constructs in a docker-compose file.

        `trivy config` does not analyse compose files at all (measured v0.69.3:
        rc 0 with `Results` omitted), so this is parsed directly with PyYAML.
        `yaml.compose` is used deliberately instead of `safe_load`: it returns
        the node tree with source marks, so each finding carries the exact line
        a reviewer needs.

        Checks are scoped to ``services.<name>``: a `privileged` key under
        `environment` or `build.args` is data, not the compose flag, and must
        never fire. YAML `<<` merge keys (anchors/aliases) ARE resolved — at the
        service level AND at the services mapping (`services: {<<: *svcs}`) — so
        a service that merges `x-h: &h {privileged: true}` is reported exactly
        as `docker compose config` would apply it. Resolution is memoised per
        mapping node and bounded (``_MAX_COMPOSE_MERGE_DEPTH`` /
        ``_MAX_COMPOSE_MERGE_SOURCES``).

        Values of the security-relevant keys (`privileged`, `network_mode`,
        `pid`, `cap_add`, `volumes`) are interpolation-expanded first
        (`$VAR`, `${VAR}`, `${VAR:-default}`, `${VAR-default}`), because
        `privileged: ${PRIV:-true}` renders true in `docker compose config`
        while the raw scalar is merely a string.

        Rule: a compose value whose effective content we cannot determine is
        UNCHECKED (degraded, `ScannerPartialRunError`), not clean. That covers
        unresolved interpolation, a mapping/sequence where a scalar is needed,
        and cross-file indirection (`include:`, service `extends.file`) when it
        cannot be resolved. When `scan()` has resolved the references and added
        every referenced file to the compose scan set, the per-file parse skips
        the indirection instead of degrading — the included services are
        checked from their own file.

        Why a bound, and why degrade: YAML anchor/merge semantics are a rabbit
        hole. A compose file we cannot fully resolve is reported as UNCHECKED
        (degraded) — the same fail-closed rule the rest of this engine enforces
        — rather than clean, and rather than a failed engine that drops findings
        already collected. A RecursionError (pathologically deep YAML) takes the
        same path.

        Known YAML-1.2 difference (documented, deliberately not fixed): PyYAML
        rejects DUPLICATE anchor names (`ComposerError: found duplicate
        anchor`). YAML 1.2 lets a later anchor redefine an earlier one; under
        PyYAML such a file degrades (`ScannerPartialRunError`) rather than being
        silently skipped — fail-closed.

        Findings (engine `trivy-iac`, language `docker-compose`):
          * ``privileged: true`` -> COMPOSE-PRIVILEGED (CRITICAL)
          * ``network_mode: host`` -> COMPOSE-NETWORK-HOST (HIGH)
          * ``pid: host`` -> COMPOSE-PID-HOST (HIGH)
          * ``cap_add`` SYS_ADMIN/ALL -> COMPOSE-CAP-ADD (CRITICAL)
          * a docker.sock bind/volume -> COMPOSE-DOCKER-SOCK (CRITICAL)
          * an absolute host bind mount -> COMPOSE-HOST-BIND (HIGH)
        """
        try:
            root = yaml.compose(text)
        except yaml.YAMLError as e:
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                reason=f"docker-compose file {target} is not valid YAML: {e}",
            ) from e
        except RecursionError as e:
            # Pathologically deep YAML: report UNCHECKED (degraded), never clean.
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                reason=(
                    f"docker-compose file {target} is too deeply nested to parse "
                    f"({type(e).__name__}); the file was not checked"
                ),
            ) from e
        if not isinstance(root, MappingNode):
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                reason=(
                    f"docker-compose file {target} has no YAML mapping at its root "
                    "(empty or not a compose document)"
                ),
            )

        # Process env by default (compose interpolation reads it); tests may
        # pass an explicit mapping.
        resolved_env: Mapping[str, str] = os.environ if env is None else env

        # Per-file memoised, bounded merge resolution (see _mapping_entries).
        cache: dict[int, list[tuple[Node, Node]]] = {}
        budget = _MergeBudget()

        matches: list[VulnerabilityMatch] = []
        seen: set[tuple[str, str, int]] = set()
        lines = text.splitlines()

        def _add(
            pattern: str,
            node: Node,
            service: str,
            vulnerability_type: VulnerabilityType,
            severity: VulnerabilitySeverity,
            title: str,
            description: str,
            remediation: str,
        ) -> None:
            line = node.start_mark.line + 1
            key = (pattern, service, line)
            if key in seen:  # two flow-style services on one line = two findings
                return
            seen.add(key)
            index = node.start_mark.line
            snippet = lines[index].strip() if 0 <= index < len(lines) else ""
            matches.append(
                VulnerabilityMatch(
                    engine=ScanEngine.TRIVY_IAC,
                    # The service is part of the id: two flow-style services can
                    # share one line, and their findings must stay distinct
                    # through the detector's report merge.
                    id=f"trivy_config_{pattern}_{service}_{target}_{line}",
                    vulnerability_type=vulnerability_type,
                    severity=severity,
                    # Template/construct-deterministic, like a trivy config rule.
                    confidence=VulnerabilityConfidence.HIGH,
                    file_path=target,
                    language=_COMPOSE_LANGUAGE,
                    line_start=line,
                    line_end=line,
                    pattern_id=pattern,
                    title=title,
                    description=description,
                    code_snippet=snippet,
                    remediation_advice=remediation,
                    references=["https://docs.docker.com/compose/compose-file/"],
                    matched_patterns=[pattern],
                )
            )

        def _add_docker_sock(node: Node, service: str) -> None:
            _add(
                _COMPOSE_PATTERN_DOCKER_SOCK,
                node,
                service,
                VulnerabilityType.PRIVILEGE_ESCALATION,
                VulnerabilitySeverity.CRITICAL,
                "Docker socket mounted into a container",
                f"Service {service!r} mounts the Docker daemon socket. The "
                "container can then control the host Docker daemon, which is "
                "equivalent to root on the host.",
                _DOCKER_SOCK_REMEDIATION,
            )

        def _add_host_bind(node: Node, service: str) -> None:
            _add(
                _COMPOSE_PATTERN_HOST_BIND,
                node,
                service,
                VulnerabilityType.INFORMATION_DISCLOSURE,
                VulnerabilitySeverity.HIGH,
                "Host filesystem bind mount in docker-compose",
                f"Service {service!r} bind-mounts an absolute host path outside "
                "the repository, exposing host files to the container.",
                "Mount only a repository-relative path, with the narrowest "
                "permissions the service needs (prefer `:ro`).",
            )

        def _check_volume_item(item: Node, service: str) -> None:
            if isinstance(item, ScalarNode):
                # Short syntax: `source:target[:mode]`. Only the SOURCE can be a
                # host socket or host path; a bare container path is anonymous.
                # Interpolation is expanded first: ${SOCK:-/var/run/docker.sock}.
                value = _compose_scalar_value(
                    item, resolved_env, key="volumes", service=service
                ).strip()
                source = _compose_volume_source(value)
                if source is not None and _DOCKER_SOCK_MARKER in source:
                    _add_docker_sock(item, service)
                elif source is not None and source.startswith("/"):
                    _add_host_bind(item, service)
                return
            if isinstance(item, MappingNode):
                # Long syntax: {type: bind, source: ..., target: ...}.
                source_node = _mapping_lookup(item, "source", cache=cache, budget=budget)
                if source_node is None:
                    source_node = _mapping_lookup(item, "src", cache=cache, budget=budget)
                if source_node is None:
                    return  # named/anonymous volume: no host source to evaluate
                source = _compose_scalar_value(
                    source_node, resolved_env, key="volumes.source", service=service
                ).strip()
                if _DOCKER_SOCK_MARKER in source:
                    _add_docker_sock(source_node, service)
                elif source.startswith("/"):
                    _add_host_bind(source_node, service)
                return
            raise _ComposeUnresolvableError(
                f"service {service!r}.volumes contains a {type(item).__name__} we cannot evaluate"
            )

        try:
            # Cross-file indirection: when the caller (scan()) has resolved it,
            # every referenced file is already in the compose scan set and is
            # checked on its own; here it is skipped. A direct caller that has
            # NOT resolved it must still see the file as UNCHECKED, never clean.
            # Root keys are checked here; a service-level `extends` is caught in
            # the per-service loop below, which can name the service.
            if not indirections_resolved:
                for indirection in ("include", "extends"):
                    if _mapping_lookup(root, indirection, cache=cache, budget=budget) is not None:
                        raise _ComposeUnresolvableError(
                            f"the document root uses cross-file {indirection!r} indirection"
                        )

            services = _mapping_lookup(root, "services", cache=cache, budget=budget)
            if services is None:
                return matches
            if not isinstance(services, MappingNode):
                raise ScannerPartialRunError(
                    "trivy-iac",
                    0,
                    reason=(f"docker-compose file {target} has a non-mapping 'services' value"),
                )

            # `services: {<<: *svcs}` applies the merged services; iterate the
            # EFFECTIVE entries, never the raw mapping (raw would see only `<<`).
            for service_key, service_node in _mapping_entries(services, cache=cache, budget=budget):
                service = _scalar_text(service_key) or "<unnamed>"
                if not isinstance(service_node, MappingNode):
                    raise _ComposeUnresolvableError(
                        f"service {service!r} is a {type(service_node).__name__}, not a mapping"
                    )
                for key_node, value_node in _mapping_entries(
                    service_node, cache=cache, budget=budget
                ):
                    key = _scalar_text(key_node)
                    if key in ("extends", "include"):
                        # `extends` here is a same-file service reference or an
                        # in-repo file that scan() already queued; `include` is
                        # not a service-level key at all. Neither contributes a
                        # security-relevant value to THIS service's checks.
                        if not indirections_resolved:
                            raise _ComposeUnresolvableError(
                                f"service {service!r} uses cross-file {key!r} indirection"
                            )
                        continue
                    if key == "privileged":
                        if _compose_bool_value(value_node, resolved_env, key=key, service=service):
                            _add(
                                _COMPOSE_PATTERN_PRIVILEGED,
                                key_node,
                                service,
                                VulnerabilityType.PRIVILEGE_ESCALATION,
                                VulnerabilitySeverity.CRITICAL,
                                "Privileged container in docker-compose",
                                f"Service {service!r} sets `privileged: true`, giving "
                                "the container all host capabilities and effectively "
                                "root access to the host.",
                                "Remove `privileged: true` and grant only the specific "
                                "Linux capabilities the service needs (`cap_add`).",
                            )
                    elif key == "network_mode":
                        if (
                            _compose_scalar_value(
                                value_node, resolved_env, key=key, service=service
                            ).strip()
                            == "host"
                        ):
                            _add(
                                _COMPOSE_PATTERN_NETWORK_HOST,
                                key_node,
                                service,
                                VulnerabilityType.PRIVILEGE_ESCALATION,
                                VulnerabilitySeverity.HIGH,
                                "Host network mode in docker-compose",
                                f"Service {service!r} uses `network_mode: host`, "
                                "sharing the host network namespace and exposing host "
                                "services and interfaces to the container.",
                                "Use a dedicated compose network; publish only the "
                                "specific ports the service needs.",
                            )
                    elif key == "pid":
                        if (
                            _compose_scalar_value(
                                value_node, resolved_env, key=key, service=service
                            ).strip()
                            == "host"
                        ):
                            _add(
                                _COMPOSE_PATTERN_PID_HOST,
                                key_node,
                                service,
                                VulnerabilityType.PRIVILEGE_ESCALATION,
                                VulnerabilitySeverity.HIGH,
                                "Host PID namespace in docker-compose",
                                f"Service {service!r} uses `pid: host`, sharing the "
                                "host PID namespace so the container can see and "
                                "signal host processes.",
                                "Remove `pid: host`; use a dedicated PID namespace.",
                            )
                    elif key == "cap_add":
                        for capability, capability_node in _compose_capabilities(
                            value_node, resolved_env, service=service
                        ):
                            if capability in ("SYS_ADMIN", "ALL"):
                                _add(
                                    _COMPOSE_PATTERN_CAP_ADD,
                                    capability_node,
                                    service,
                                    VulnerabilityType.PRIVILEGE_ESCALATION,
                                    VulnerabilitySeverity.CRITICAL,
                                    "Dangerous Linux capability in docker-compose",
                                    f"Service {service!r} adds the {capability} "
                                    "capability. SYS_ADMIN/ALL grant broad host "
                                    "control (mount, namespaces, ptrace) and are "
                                    "effectively a container escape.",
                                    "Drop SYS_ADMIN/ALL; grant only the narrow "
                                    "capability the service needs, or use "
                                    "`cap_drop: [ALL]` with an explicit allow-list.",
                                )
                                break
                    elif key == "volumes":
                        if not isinstance(value_node, SequenceNode):
                            raise _ComposeUnresolvableError(
                                f"service {service!r}.volumes is a "
                                f"{type(value_node).__name__}, not a list"
                            )
                        for item in value_node.value:
                            _check_volume_item(item, service)
        except _ComposeUnresolvableError as e:
            # A value/key whose effective content we cannot determine (unresolved
            # interpolation, a non-evaluable value, cross-file indirection):
            # UNCHECKED (degraded), never clean. Findings so far ride along.
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                partial_findings=list(matches),
                reason=(
                    f"docker-compose file {target} cannot be checked: {e}; "
                    "the file is UNCHECKED (degraded)"
                ),
            ) from e
        except _MergeBudgetExceededError as e:
            # Bounded work exceeded: report the file UNCHECKED (degraded) and
            # keep the findings found so far. Never clean, never a failed engine.
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                partial_findings=list(matches),
                reason=(
                    f"docker-compose file {target} exceeds the YAML merge budget "
                    f"({e}); the file was only partially checked"
                ),
            ) from e
        except RecursionError as e:
            raise ScannerPartialRunError(
                "trivy-iac",
                0,
                partial_findings=list(matches),
                reason=(
                    f"docker-compose file {target} is too deeply nested to resolve "
                    f"({type(e).__name__}); the file was only partially checked"
                ),
            ) from e

        return matches

    @staticmethod
    def _as_str_list(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]

    def get_status(self) -> dict:
        return {
            "available": self.trivy_available,
            "engine": "trivy config",
            "description": (
                "Infrastructure-as-code (Dockerfile/Kubernetes/Terraform/"
                "docker-compose) misconfiguration scanning"
            ),
        }
