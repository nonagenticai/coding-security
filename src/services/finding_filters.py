"""Post-merge false-positive filters for the security scan.

Applied by ``SecurityVulnerabilityDetector`` right after every engine's findings
are merged. Each rule either DROPS a finding or DOWNGRADES it, and every action
is COUNTED by reason in the returned ``suppressed`` dict so the scan result can
say exactly what was filtered — a suppression is never silent.

Rules (in evaluation order; a dropped finding is counted under the first reason
that dropped it):

* ``inline_suppression`` — a COMMENT on the finding's reported line carries
  a marker that covers it (semgrep: ``line_start`` only; other engines on a
  Python file: ``line_start`` extended over its open brackets): ``# nosec [Bxxx,...]``, ``# noqa: Sxxx``,
  ``# pragma: allowlist secret`` or ``nosemgrep[: rule]`` (semgrep findings
  only). Python comments come from ``tokenize`` (a file it cannot tokenize
  has no comments); elsewhere a ``#`` / ``//`` outside string quotes. A marker
  inside a string literal waives nothing.
* ``assert_in_tests`` — bandit B101 (assert) in a test path.
* ``credential_label`` — SOURCE files only: a "hardcoded credential" line whose
  EVERY quoted literal is a mapping key or a label (a dotted catalogue key, an
  enum value EQUAL to its own name: ``CLIENT_SECRET_BASIC =
  "client_secret_basic"``, or a pure template reference ``"${VAR}"``; one with
  a default is a value, not a label). Dotenv files are the one config type with
  a NARROWER version of this rule: a value equal to its key, a template
  reference, empty, or an obvious placeholder token is suppressed; any other
  value is a real secret and is kept.
* ``object_id`` — a hex-entropy "secret" where an id-named key is assigned a
  MongoDB ObjectId and every hex run on the line is an ObjectId.
* ``sql_constant_interpolation`` — a Python ``.execute(f"...")`` whose every
  interpolation is a constant proven from the module AST (a name bound once,
  at module level, to a literal) or an un-rebound ``int``/``float``/``len``;
  never in a file using ``import *`` / ``globals(`` / ``vars(`` / ``setattr(``.
* ``test_path_downgraded`` — NOT dropped: any other finding in a test path
  (``tests/``, ``test/``, ``e2e/``, ``__tests__/``, ``testdata/``,
  ``conftest.py``, ``*_test.go``, ``*.test.*`` / ``*.spec.*`` JS/TS) is lowered
  to LOW, except provider-specific real-secret detections (a leaked token in a
  test is still a leak). A private-key detection that is a bare PEM header
  with no key material next to it is not a leaked key, so it is downgraded
  like any other test finding.

Every rule fails closed: anything it cannot prove keeps the finding.
"""

from __future__ import annotations

import ast
import io
import os
import re
import textwrap
import time
import tokenize
from collections.abc import Iterable, Mapping
from pathlib import PurePath

from services.security_detector import (
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)

REASON_INLINE = "inline_suppression"
REASON_ASSERT_IN_TESTS = "assert_in_tests"
REASON_CREDENTIAL_LABEL = "credential_label"
REASON_OBJECT_ID = "object_id"
REASON_SQL_CONSTANT = "sql_constant_interpolation"
REASON_TEST_DOWNGRADE = "test_path_downgraded"

# Statement-span extension cap (lines after the reported line).
_MAX_SPAN_LINES = 15

# --------------------------------------------------------------------------
# Test / fixture paths
# --------------------------------------------------------------------------

# Only unambiguous test directories: ``spec`` / ``specs`` / ``fixtures`` also
# name production code (API specs, seed data), so they count only when they sit
# under one of these. ``test_*.py`` / ``*_test.py`` (``test_executor.py``,
# ``ab_test.py``) are tests only under a test directory, which the directory
# rule already covers.
_TEST_DIRS = frozenset({"tests", "test", "e2e", "__tests__", "testdata"})
_TEST_BASENAME = re.compile(
    r"^(?:.*_test\.go|conftest\.py|.*\.(?:test|spec)\.(?:js|ts|jsx|tsx|mjs))$"
)


def is_test_path(file_path: str, root: str | None = None) -> bool:
    """True when ``file_path`` (relative to ``root`` when given) is a test or
    fixture file. Only path segments BELOW ``root`` are considered, so a
    checkout that happens to live under ``/tmp/tests/`` is not all-test."""
    rel = file_path
    if root:
        try:
            rel = os.path.relpath(os.path.abspath(file_path), root)
        except ValueError:
            rel = file_path
        if rel.startswith(".."):
            rel = file_path
    parts = PurePath(rel).parts
    if not parts:
        return False
    if any(p in _TEST_DIRS for p in parts[:-1]):
        return True
    return bool(_TEST_BASENAME.match(parts[-1]))


# --------------------------------------------------------------------------
# Inline suppression markers
# --------------------------------------------------------------------------

# Searched ONLY in comment text (see ``_comment_texts``): a marker inside a
# string literal (``cmd + "#nosec"``, ``"http://h/#nosec"``) waives nothing.
_NOSEC = re.compile(r"\bnosec\b(?P<ids>(?:[\s:]+[BS]\d{3}(?:\s*,\s*[BS]\d{3})*)?)")
_NOQA = re.compile(r"\bnoqa\s*:\s*(?P<ids>[A-Z]+\d+(?:[\s,]+[A-Z]+\d+)*)")
_ALLOWLIST_SECRET = re.compile(r"pragma:\s*allowlist[ -]secret")
_NOSEMGREP = re.compile(r"\bnosemgrep\b(?:\s*:\s*(?P<ids>[\w.\-]+(?:\s*,\s*[\w.\-]+)*))?")
_RULE_ID = re.compile(r"[BS](\d{3})")


def _code_to_type(code: str) -> VulnerabilityType | None:
    """bandit ``Bnnn`` / ruff flake8-bandit ``Snnn`` -> the type bandit reports
    that test as (ruff's S-codes reuse bandit's numbers). Unmapped bandit ids
    fall back to INFORMATION_DISCLOSURE, exactly as ``bandit_scanner`` types
    its own unmapped findings."""
    from services.bandit_scanner import _TEST_ID_TO_TYPE

    m = _RULE_ID.fullmatch(code.strip())
    if not m:
        return None
    return _TEST_ID_TO_TYPE.get(f"B{m.group(1)}", VulnerabilityType.INFORMATION_DISCLOSURE)


def _split_ids(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [t for t in re.split(r"[\s,:]+", raw) if t]


def _ids_cover(ids: list[str], finding: VulnerabilityMatch) -> bool:
    """Do the rule ids of a ``nosec`` / ``noqa`` marker cover ``finding``?

    A bandit finding has its own id, so only that id waives it (``# noqa: S603``
    does not waive B607, exactly as bandit itself behaves). Any other engine's
    finding is covered when one id maps to its vulnerability type."""
    if finding.engine == "bandit":
        own = _RULE_ID.fullmatch(finding.pattern_id)
        if own:
            return any((m := _RULE_ID.fullmatch(i)) and m.group(1) == own.group(1) for i in ids)
    ftype = finding.vulnerability_type
    return any(_code_to_type(i) == ftype for i in ids)


def _comment_suppresses(comment: str, finding: VulnerabilityMatch) -> bool:
    """Does an inline marker in ``comment`` (comment text only) cover ``finding``?"""
    ftype = finding.vulnerability_type
    line = comment
    m = _NOSEC.search(line)
    if m:
        ids = _split_ids(m.group("ids"))
        if not ids:
            return True  # bare nosec: any category
        if _ids_cover(ids, finding):
            return True
    m = _NOQA.search(line)
    if m:
        ids = [i for i in _split_ids(m.group("ids")) if _RULE_ID.fullmatch(i)]
        if _ids_cover(ids, finding):
            return True
    if _ALLOWLIST_SECRET.search(line) and ftype == VulnerabilityType.HARDCODED_CREDENTIALS:
        return True
    m = _NOSEMGREP.search(line)
    if m and finding.engine == "semgrep":
        # nosemgrep is semgrep's own marker: it never waives another engine.
        ids = _split_ids(m.group("ids"))
        if not ids:
            return True
        if any(finding.pattern_id == i or finding.pattern_id.endswith("." + i) for i in ids):
            return True
    return False


def _line_comment(
    line: str, comments: tuple[str, ...], open_backtick: bool = False
) -> tuple[str | None, bool]:
    """The comment text of a non-Python ``line`` (from the first comment start
    that is outside string quotes to the end of the line), and whether a
    backtick string is still open at its end. A ``#`` counts only at the line
    start or after whitespace (``http://h/#x`` is not a comment)."""
    quote: str | None = "`" if open_backtick else None
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "\"'`":
            quote = c
            i += 1
            continue
        for cs in comments:
            if line.startswith(cs, i) and (cs != "#" or i == 0 or line[i - 1].isspace()):
                return line[i:], False
        i += 1
    return None, quote == "`"


def _python_comments(text: str) -> dict[int, str]:
    """COMMENT tokens of a Python source by 1-based line. A file ``tokenize``
    cannot read has NO comments: its markers waive nothing (a regex guess could
    read a ``# nosec`` inside a string as a comment)."""
    found: dict[int, str] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                found[tok.start[0]] = tok.string
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return {}
    return found


def _comment_texts(
    lines: list[str], file_path: str, py_comments: dict[int, str] | None
) -> list[str | None]:
    """Per line (index 0 = line 1), the comment text on it, or None. A
    backtick string (JS template literal, Go raw string) carries over lines,
    so a marker inside one is not a comment."""
    if py_comments is not None:
        return [py_comments.get(i + 1) for i in range(len(lines))]
    comments = _comment_starts(file_path)
    out: list[str | None] = []
    open_backtick = False
    for line in lines:
        comment, open_backtick = _line_comment(line, comments, open_backtick)
        out.append(comment)
    return out


def _comment_starts(file_path: str) -> tuple[str, ...]:
    ext = os.path.splitext(file_path)[1].lower()
    if ext in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".java", ".go", ".rs", ".c", ".h"}:
        return ("//",)
    if ext in {".cpp", ".cc", ".cxx", ".hpp", ".cs", ".swift", ".kt"}:
        return ("//",)
    if ext == ".php":
        return ("//", "#")
    return ("#",)


def _bracket_delta(
    line: str, open_string: str | None, comments: tuple[str, ...]
) -> tuple[int, str | None]:
    """Net bracket depth change of ``line``, ignoring brackets inside string
    literals and comments. ``open_string`` is a multi-line string delimiter
    (triple quote / backtick) carried over from the previous line."""
    depth = 0
    i = 0
    n = len(line)
    quote = open_string
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if line.startswith(quote, i):
                i += len(quote)
                quote = None
                continue
            i += 1
            continue
        if any(line.startswith(cs, i) for cs in comments):
            break
        if line.startswith('"""', i) or line.startswith("'''", i):
            quote = line[i : i + 3]
            i += 3
            continue
        if c in "\"'`":
            quote = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        i += 1
    # A single-line quote never continues onto the next line.
    if quote in ('"', "'"):
        quote = None
    return depth, quote


def statement_span(lines: list[str], finding: VulnerabilityMatch) -> tuple[int, int]:
    """1-based inclusive (start, end) of the finding's statement.

    ``line_start``, extended forward while the brackets opened on it are
    unbalanced (cap ``_MAX_SPAN_LINES``). ``line_end`` is ignored: an engine's
    range can cover a whole block. If the brackets never balance within the
    cap, fall back to ``line_start`` only.
    """
    start = max(finding.line_start, 1)
    end = start
    if start > len(lines):
        return start, end
    comments = _comment_starts(finding.file_path)
    depth = 0
    open_string: str | None = None
    last = min(len(lines), start + _MAX_SPAN_LINES)
    for idx in range(start, last + 1):
        delta, open_string = _bracket_delta(lines[idx - 1], open_string, comments)
        depth += delta
        if idx >= end and depth <= 0 and open_string is None:
            return start, idx
    return start, end


def _inline_suppressed(
    lines: list[str], comments: list[str | None], finding: VulnerabilityMatch
) -> bool:
    # semgrep counts markers on the finding's first line only (its own rule).
    # Forward span extension only for Python: there a bracketed continuation
    # holds call arguments/literals. In brace languages the brackets opened on
    # the reported line can enclose a whole callback body, so a marker on a
    # later statement would waive this one -- only ``line_start`` counts.
    if finding.engine != "semgrep" and _is_python(finding.file_path):
        s, e = statement_span(lines, finding)
    else:
        s = e = max(finding.line_start, 1)
    for i in range(s, min(e, len(lines)) + 1):
        comment = comments[i - 1]
        if comment and _comment_suppresses(comment, finding):
            return True
    return False


# --------------------------------------------------------------------------
# Credential labels / template references
# --------------------------------------------------------------------------

_CREDENTIAL_WORD = re.compile(r"password|passwd|secret|token|key|credential|auth", re.IGNORECASE)
# Identifier/key shape: words joined by `_` `.` `:` (snake, SCREAMING, dotted
# i18n keys). A single word ("password") or dash-joined phrase
# ("super-secret-password") is a plausible weak password and is kept.
_LABEL_CHARS = re.compile(r"[A-Za-z]+(?:[._:][A-Za-z]+)+")
# PURE template references only. A reference that carries a default
# (``${X:-val}``, ``${X-val}``, ``${X:=val}``, ``{{ .pw | default "v" }}``)
# ships that default as the value, so it is not a label. ``$(...)`` runs a
# command whose text can be the value (``$(echo hunter2)``): not a reference.
_TEMPLATE_REF = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{(?:(?!\}\}).)*\}\}|%\([^)]*\)[a-z]")
# A ``{{ ... }}`` holding a literal or a fallback function carries a value.
_TEMPLATE_VALUE = re.compile(r"[\"'`]|\b(?:default|coalesce|or|printf)\b")
_NAME = r"(?P<name>[A-Za-z_][\w.\-]*)[\"']?\s*"
# `name = "value"` / `"name": "value"` (never `==`, `!=`, `<=`, `>=`).
_ASSIGNED_QUOTED = re.compile(
    _NAME + r"(?<![=!<>:])[:=](?![=:])\s*[rRbBuU]{0,2}(?P<q>[\"'])(?P<v>(?:\\.|(?!(?P=q)).)*)(?P=q)"
)
_ANY_QUOTED = re.compile(r"(?:(?<!\w)[rRbBuU]{1,2})?(?P<q>[\"'])(?P<v>(?:\\.|(?!(?P=q)).)*)(?P=q)")
# The name a quoted literal is directly assigned to: the text BEFORE it ends
# in `name = ` / `"name": ` (never `==`, `!=`, `<=`, `>=`, `:=`, `::`).
_NAME_BEFORE = re.compile(_NAME + r"(?<![=!<>:])[:=]\s*$")
# A mapping key: the literal is followed by `:` (not `::`).
_KEY_AFTER = re.compile(r"\s*:(?!:)")
# A literal before ``:`` is also how ``if pw == "x":``, ``lambda pw="x":`` and
# ``case "x":`` end. Lines opening with a statement keyword never hold keys.
_STATEMENT_HEAD = re.compile(
    r"\s*(?:if|elif|else|while|for|with|lambda|case|match|assert|return|yield|def|except|try)\b"
)


def _is_mapping_key(line: str, lit: re.Match[str]) -> bool:
    """A dict/YAML-style key: followed by ``:`` AND opening an entry -- the
    literal starts the line or directly follows ``{`` / ``,``."""
    colon = _KEY_AFTER.match(line, lit.end())
    if colon is None or _STATEMENT_HEAD.match(line):
        return False
    prefix = line[: lit.start()].rstrip()
    if not (prefix == "" or prefix.endswith(("{", ","))):
        return False
    # ``"password":`` with the value on the next line: the value is unseen here.
    rest = line[colon.end() :].strip()
    return rest != "" and not rest.startswith("#")


#: A dotted/attribute mapping key directly before a literal
#: (`PlayOutcome.NO_SECRET: "simulator_no_secret"`). A dot is REQUIRED: a plain
#: identifier key is a config value holder, not an enum member, and the plan is
#: to keep those. Not preceded by a word/quote char so a quoted string key
#: (`"auth.password": ...`) never matches.
_DOTTED_KEY_BEFORE = re.compile(
    r"(?<![\w.\"'])(?P<key>[A-Za-z_][\w\-]*(?:\.[A-Za-z_][\w\-]*)+)\s*:(?![=:])\s*$"
)
#: An identifier-shaped enum label: letters joined by `_ . : -`, with no digits
#: and no spaces. A real password or token almost always carries a digit or a
#: symbol outside this set, which keeps it a finding.
_ENUM_LABEL_VALUE = re.compile(r"[A-Za-z._:\-]+")


def _is_enum_label_value(line: str, lit: re.Match[str]) -> bool:
    """True when the literal is the VALUE of a dotted/attribute-keyed mapping
    entry whose key ends in a credential word, and the value is itself
    identifier-shaped (``PlayOutcome.NO_SECRET: "simulator_no_secret"``).

    Deliberately narrow: only mapping values (never assignments), only a dotted
    key ending in a credential word, only letters/``._:-`` in the value, and
    never a provider-token shape. Plain string keys and digit-bearing values
    stay findings.
    """
    key_match = _DOTTED_KEY_BEFORE.search(line, 0, lit.start())
    if key_match is None:
        return False
    key_tail = key_match.group("key").rsplit(".", 1)[-1]
    if not _CREDENTIAL_WORD.search(key_tail):
        return False
    value = lit.group("v")
    if _ENUM_LABEL_VALUE.fullmatch(value) is None:
        return False
    if not _CREDENTIAL_WORD.search(value):
        return False
    # A provider token (AWS/GitHub/Slack/PEM...) is a secret by shape. Its
    # digits/format already fail _ENUM_LABEL_VALUE; this is belt and braces.
    return _PROVIDER_SHAPE.search(value) is None


# YAML / env style unquoted value: `KEY: value` or `KEY=value`.
_ASSIGNED_BARE = re.compile(
    _NAME + r"(?<![=!<>:])[:=](?![=:])\s*(?P<v>[^\s#\"'][^#]*?)\s*(?:#.*)?$"
)

_CREDENTIAL_LABEL_RULES = frozenset({"hardcoded_password_1", "detect-secrets:Secret Keyword"})
_CREDENTIAL_LABEL_BANDIT = frozenset({"B105", "B106", "B107"})
# credential_label applies to SOURCE files only. In config files (yaml, ini,
# json, compose, Dockerfile) `POSTGRES_PASSWORD: postgres_password` IS the
# shipped password, however label-shaped it looks. Dotenv files get their own,
# NARROWER placeholder rule below (they are the one config type we now scan for
# secrets, and their committed placeholders are otherwise reported as HIGH).
_LABEL_SOURCE_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".cs",
        ".rs",
    }
)
_NORMALISE_SEPARATORS = re.compile(r"[-.:]")


def extract_literal_values(line: str) -> list[tuple[str | None, str]]:
    """Every literal a credential finding on ``line`` may be about, as
    ``(assigned name or None, value)``: all assignment / mapping values, else
    all quoted literals, else the unquoted (YAML/env) assigned value."""
    assigned = [(m.group("name"), m.group("v")) for m in _ASSIGNED_QUOTED.finditer(line)]
    if assigned:
        return assigned
    quoted: list[tuple[str | None, str]] = [
        (None, m.group("v")) for m in _ANY_QUOTED.finditer(line)
    ]
    if quoted:
        return quoted
    m = _ASSIGNED_BARE.search(line)
    if m:
        return [(m.group("name"), m.group("v").rstrip(",;"))]
    return []


def is_template_reference(value: str) -> bool:
    """True when ``value`` is nothing but pure template references."""
    stripped = value.strip()
    refs = list(_TEMPLATE_REF.finditer(stripped))
    if not refs or _TEMPLATE_REF.sub("", stripped).strip():
        return False
    return not any(
        r.group(0).startswith("{{") and _TEMPLATE_VALUE.search(r.group(0)[2:-2]) for r in refs
    )


def _normalised(text: str) -> str:
    return _NORMALISE_SEPARATORS.sub("_", text).lower()


def is_credential_label(value: str, name: str | None = None) -> bool:
    """A label/identifier or a pure template reference, not a secret value.

    A label is identifier-shaped, contains a credential word, AND is either a
    dotted catalogue key (>= 2 dots: ``admin.form.error.sms_api_key``) or
    EQUALS the last dotted component of the name it is assigned to,
    case-insensitively with ``-`` ``.`` ``:`` read as ``_`` (enum style:
    ``CLIENT_SECRET_BASIC = "client_secret_basic"``). The empty string and
    plausible passwords (``password = "my_password"``) are not.
    """
    stripped = value.strip()
    if not stripped:
        return False
    if is_template_reference(stripped):
        return True
    if not (_LABEL_CHARS.fullmatch(stripped) and _CREDENTIAL_WORD.search(stripped)):
        return False
    if stripped.count(".") >= 2:
        return True
    if not name:
        return False
    last = name.strip("\"'").rsplit(".", 1)[-1]
    return bool(last) and _normalised(last) == _normalised(stripped)


def line_is_credential_label(line: str) -> bool:
    """True only when EVERY quoted literal on ``line`` is a mapping key, an
    enum label value, or a label assigned to its own name (with no quoted
    literal: the unquoted assigned value must be a label)."""
    literals = list(_ANY_QUOTED.finditer(line))
    if not literals:
        m = _ASSIGNED_BARE.search(line)
        return bool(m) and is_credential_label(m.group("v").rstrip(",;"), m.group("name"))
    for lit in literals:
        if _is_mapping_key(line, lit):
            continue
        # `PlayOutcome.NO_SECRET: "simulator_no_secret"`: the quoted literal is
        # the VALUE of an enum-style entry, not a key and not its own name.
        if _is_enum_label_value(line, lit):
            continue
        before = _NAME_BEFORE.search(line, 0, lit.start())
        if not is_credential_label(lit.group("v"), before.group("name") if before else None):
            return False
    return True


def _continuation_is_label(line: str) -> bool:
    """A continuation line of a credential statement: one with no literal and
    no assignment (``)``, a bare name) is neutral, anything else must pass."""
    if not _ANY_QUOTED.search(line) and not _ASSIGNED_BARE.search(line):
        return True
    return line_is_credential_label(line)


def _is_label_source(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in _LABEL_SOURCE_EXTS


# Dotenv files (``.env``, ``.env.example``, ``.env.production``) are now scanned
# by detect-secrets, so a committed placeholder must not become a HIGH finding.
# The rule is deliberately NARROWER than the source one: only a value EQUAL to
# its key name, a pure template reference, an empty value, or an obvious
# placeholder token is suppressed. Any other value (``DB_PASSWORD=hunter2``)
# is kept at full severity.
_PLACEHOLDER_VALUES = frozenset(
    {
        "changeme",
        "change_me",
        "changeit",
        "change_it",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "fake",
        "tbd",
        "todo",
        "none",
        "null",
        "secret",
        "password",
        "passwd",
        "token",
        "apikey",
        "api_key",
    }
)
_PLACEHOLDER_PATTERN = re.compile(
    r"(?:your(?:_.*)?|.*_placeholder|replace_me|not_a_real.*|<[^>]*>|\*+|x{3,})"
)
_DOTENV_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][\w.\-]*)\s*=\s*(?P<value>.*?)\s*$"
)


def _is_dotenv_file(path: str) -> bool:
    name = PurePath(path).name
    return name == ".env" or name.startswith(".env.")


def _strip_dotenv_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def is_dotenv_placeholder(value: str, name: str | None = None) -> bool:
    """A dotenv value that is clearly a label/placeholder, never a secret."""
    stripped = _strip_dotenv_quotes(value)
    if not stripped:
        return True
    if is_template_reference(stripped):
        return True
    normalised = _normalised(stripped)
    if name and normalised == _normalised(name):
        return True
    return normalised in _PLACEHOLDER_VALUES or bool(_PLACEHOLDER_PATTERN.fullmatch(normalised))


def line_is_dotenv_placeholder(line: str) -> bool:
    """True when a dotenv assignment line carries only a placeholder value."""
    m = _DOTENV_ASSIGNMENT.match(line)
    if m is None:
        return False
    return is_dotenv_placeholder(m.group("value"), m.group("name"))


def _is_credential_label_candidate(finding: VulnerabilityMatch) -> bool:
    if not (_is_label_source(finding.file_path) or _is_dotenv_file(finding.file_path)):
        return False
    if finding.vulnerability_type != VulnerabilityType.HARDCODED_CREDENTIALS:
        return False
    if finding.pattern_id in _CREDENTIAL_LABEL_BANDIT:
        return True
    if finding.pattern_id not in _CREDENTIAL_LABEL_RULES:
        return False
    # A provider token shape (AWS/Slack/PEM/...) is a secret by its shape.
    return not _is_provider_secret(finding)


# --------------------------------------------------------------------------
# Hex entropy: MongoDB ObjectIds and id-named values
# --------------------------------------------------------------------------

_OBJECT_ID = re.compile(r"[0-9a-f]{24}")
# Every hex-like run on the line, quoted, backticked or bare.
_HEX_RUN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{16,}(?![0-9a-fA-F])")
_NAMED_HEX = re.compile(
    r"(?P<name>[A-Za-z_][\w\-.]*)[\"']?\s*[:=]\s*[\"'](?P<v>[0-9a-fA-F]{16,})[\"']"
)
_ID_NAME = re.compile(r"(?:^|[_\-.])(?:id|Id|ID|uuid|guid)$|[a-z0-9](?:Id|ID)$|(?:uuid|guid)$")
_OBJECT_ID_EPOCH_MIN = 1230768000  # 2009-01-01T00:00:00Z


def is_object_id(value: str, now: float | None = None) -> bool:
    if not _OBJECT_ID.fullmatch(value):
        return False
    ts = int(value[:8], 16)
    upper = (now if now is not None else time.time()) + 366 * 86400
    return _OBJECT_ID_EPOCH_MIN <= ts <= upper


def _hex_is_identifier(line: str) -> bool:
    """True only when an id-named key/name on ``line`` is directly assigned a
    MongoDB ObjectId AND every hex-like run on the line (quoted or not) is an
    ObjectId. An id name alone proves nothing (``session_id = "<64 hex>"`` is a
    token), nor does an ObjectId shape alone (``API_SECRET = "<24 hex>"``), and
    a name carrying a credential word (``client_secret_id``) is not id-named."""
    named_oid = any(
        _ID_NAME.search(m.group("name"))
        and not _CREDENTIAL_WORD.search(m.group("name"))
        and is_object_id(m.group("v"))
        for m in _NAMED_HEX.finditer(line)
    )
    if not named_oid:
        return False
    return all(is_object_id(m.group(0)) for m in _HEX_RUN.finditer(line))


# --------------------------------------------------------------------------
# Python SQL f-strings interpolating only constants
# --------------------------------------------------------------------------

_SAFE_CALLS = frozenset({"int", "float", "len"})
# ``setattr`` only when it targets a module object (``sys.modules[...]`` /
# ``__import__(...)``): ``setattr(context, ...)`` on an ordinary object cannot
# rebind a module-level name.
_DYNAMIC_BINDING = re.compile(
    r"\bimport\s+\*|\b(?:globals|vars|exec|import_module|__import__)\s*\("
    r"|\bsys\s*\.\s*modules\b"
)
_EXECUTE_NAMES = frozenset({"execute", "executemany", "executescript"})
_CONTAINERS = (ast.Tuple, ast.List, ast.Set)


def _bound_names(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Every binding of every name anywhere in ``tree`` (assignment targets,
    parameters, def/class names, imports, ``global`` declarations)."""
    bindings: dict[str, list[ast.AST]] = {}

    def add(name: str, node: ast.AST) -> None:
        bindings.setdefault(name, []).append(node)

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            add(node.id, node)
        elif isinstance(node, ast.arg):
            add(node.arg, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name, node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                add((alias.asname or alias.name).split(".")[0], node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                add(name, node)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            add(node.name, node)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            add(node.name, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(node.rest, node)
    return bindings


def _is_str_container(
    node: ast.expr, bindings: dict[str, list[ast.AST]], *, inside_frozenset: bool = False
) -> bool:
    # A module-level list/set can be mutated later (``COLS.append(u)``), so
    # only an immutable tuple (or a frozenset of literals) proves a constant.
    allowed = _CONTAINERS if inside_frozenset else (ast.Tuple,)
    if isinstance(node, allowed):
        return all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "frozenset"
        and "frozenset" not in bindings
        and not node.keywords
        and len(node.args) <= 1
        and all(_is_str_container(a, bindings, inside_frozenset=True) for a in node.args)
    )


def module_constants(source: str) -> tuple[frozenset[str], frozenset[str]] | None:
    """``(constant names, safe builtin calls)`` proven from a module's AST.

    A name is constant only if it is bound exactly once in the whole file, by a
    MODULE-level ``NAME = <value>`` whose value is a str/int literal or a
    tuple/list/set/frozenset of str literals. ``int``/``float``/``len`` are safe
    calls only while the module never rebinds them. None when it does not
    parse, or when names can be bound invisibly to the AST walk (``import *``,
    ``globals(``, ``vars(``, ``setattr(``).
    """
    if _DYNAMIC_BINDING.search(source):
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    bindings = _bound_names(tree)
    constants: set[str] = set()
    for stmt in tree.body:
        if not (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            continue
        name = stmt.targets[0].id
        if len(bindings.get(name, [])) != 1:
            continue
        value = stmt.value
        literal = isinstance(value, ast.Constant) and isinstance(value.value, (str, int))
        if literal or _is_str_container(value, bindings):
            constants.add(name)
    safe_calls = frozenset(c for c in _SAFE_CALLS if c not in bindings)
    return frozenset(constants), safe_calls


def _is_constant_expr(
    node: ast.expr, constants: frozenset[str], safe_calls: frozenset[str]
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in constants
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Name) and node.func.id in safe_calls
    return False


def _joined_str_is_constant(
    node: ast.JoinedStr, constants: frozenset[str], safe_calls: frozenset[str]
) -> bool:
    for part in node.values:
        if isinstance(part, ast.FormattedValue):
            if not _is_constant_expr(part.value, constants, safe_calls):
                return False
            spec = part.format_spec
            if isinstance(spec, ast.JoinedStr) and not _joined_str_is_constant(
                spec, constants, safe_calls
            ):
                return False
    return True


def _parse_statement(text: str) -> ast.Module | None:
    src = textwrap.dedent(text)
    for candidate in (src, src.rstrip() + "\n    pass\n"):
        try:
            return ast.parse(candidate)
        except SyntaxError:
            continue
    return None


def sql_interpolates_only_constants(statement: str, module_source: str) -> bool:
    """True when every ``.execute(...)`` in ``statement`` takes an f-string
    whose interpolations are all constants PROVEN from ``module_source`` (the
    whole file; see ``module_constants``). Anything it cannot prove (parse
    failure, a non-f-string query, a concatenation, an imported or rebound
    name, an attribute) returns False: keep."""
    return _statement_is_constant(statement, module_constants(module_source))


def _statement_is_constant(
    statement: str, proven: tuple[frozenset[str], frozenset[str]] | None
) -> bool:
    tree = _parse_statement(statement)
    if proven is None or tree is None:
        return False
    constants, safe_calls = proven
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in _EXECUTE_NAMES
        and n.args
    ]
    if not calls:
        return False
    saw_fstring = False
    for call in calls:
        query = call.args[0]
        if isinstance(query, ast.Constant) and isinstance(query.value, str):
            continue
        if not isinstance(query, ast.JoinedStr):
            return False
        if not _joined_str_is_constant(query, constants, safe_calls):
            return False
        saw_fstring = True
    return saw_fstring


# --------------------------------------------------------------------------
# Provider-specific (real) secret detections
# --------------------------------------------------------------------------

_PROVIDER_DETECT_SECRETS = frozenset(
    {
        "AWS Access Key",
        "Private Key",
        "GitHub Token",
        "GitLab Token",
        "Slack Token",
        "Stripe Access Key",
        "JSON Web Token",
        "Twilio API Key",
        "Azure Storage Account access key",
        "Discord Bot Token",
        "OpenAI Token",
        "Artifactory Credentials",
        "Cloudant Credentials",
        "IBM Cloud IAM Key",
        "IBM COS HMAC Credentials",
        "Mailchimp Access Key",
        "NPM tokens",
        "PyPI Token",
        "SendGrid API Key",
        "SoftLayer Credentials",
        "Square OAuth Secret",
        "Telegram Bot Token",
    }
)
_PROVIDER_SHAPE = re.compile(
    r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[0-9A-Za-z-]{10,}"
    r"|-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY-----"
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}"
    r"|\b[sr]k_live_[0-9A-Za-z]{16,}"
    r"|\bAIza[0-9A-Za-z_\-]{35}"
    r"|\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"
)


_PEM_HEADER = re.compile(r"BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY")
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/=]{40,}")
# Lines after a PEM header searched for key material (an ENCRYPTED key has
# Proc-Type / DEK-Info / blank lines before the base64 body).
_KEY_MATERIAL_LINES = 5


def _is_bare_pem_header(finding: VulnerabilityMatch, lines: list[str] | None) -> bool:
    """A private-key detection with no key material near it: the header string
    alone (``startswith("-----BEGIN PRIVATE KEY-----")``, a stub ``\nMIIE\n``
    body). Detectors key on the header, so this is a mention, not a leak.
    Unknown file contents -> False (treat it as a real key)."""
    is_pem = finding.pattern_id == "detect-secrets:Private Key" or (
        finding.pattern_id == "hardcoded_password_1"
        and bool(_PEM_HEADER.search(finding.code_snippet or ""))
    )
    if not is_pem or lines is None or not 0 < finding.line_start <= len(lines):
        return False
    first = finding.line_start - 1
    window = lines[first : first + 1 + _KEY_MATERIAL_LINES]
    header_line = window[0]
    m = _PEM_HEADER.search(header_line)
    after_header = header_line[m.end() :] if m else header_line
    text = "\n".join([after_header, *window[1:]])
    return not _KEY_MATERIAL.search(text)


def _is_provider_secret(finding: VulnerabilityMatch) -> bool:
    if finding.pattern_id.startswith("detect-secrets:"):
        return finding.pattern_id.split(":", 1)[1] in _PROVIDER_DETECT_SECRETS
    if finding.pattern_id == "hardcoded_password_1":
        return bool(_PROVIDER_SHAPE.search(finding.code_snippet or ""))
    return False


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def source_key(path: str) -> str:
    """The key a file's contents are stored under in ``sources``."""
    return os.path.normpath(os.path.abspath(path))


def scan_root(paths: list[str]) -> str | None:
    """The directory the scanned files share: test-path rules only look at
    path segments below it."""
    if not paths:
        return None
    abs_paths = [source_key(p) for p in paths]
    if len(abs_paths) == 1:
        return os.path.dirname(abs_paths[0])
    try:
        base = os.path.commonpath(abs_paths)
    except ValueError:
        return None
    return base if os.path.isdir(base) else os.path.dirname(base)


def _is_python(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in {".py", ".pyi", ".pyw"}


def _bump(counts: dict[str, int], reason: str) -> None:
    counts[reason] = counts.get(reason, 0) + 1


def apply_finding_filters(
    matches: Iterable[VulnerabilityMatch],
    sources: Mapping[str, str],
    root: str | None = None,
) -> tuple[list[VulnerabilityMatch], dict[str, int]]:
    """Filter merged findings. Returns (kept findings, counts by reason).

    ``sources`` maps a file path (normalised with ``source_key``) to its
    contents (the detector already holds them). A finding whose file is not in ``sources`` only gets
    the path-based rules — never a content rule it cannot check.
    """
    kept: list[VulnerabilityMatch] = []
    counts: dict[str, int] = {}
    split_cache: dict[str, list[str]] = {}
    comment_cache: dict[str, list[str | None]] = {}
    constants_cache: dict[str, tuple[frozenset[str], frozenset[str]] | None] = {}

    def lines_of(path: str) -> list[str] | None:
        key = source_key(path)
        if key not in split_cache:
            text = sources.get(key)
            if text is None:
                return None
            split_cache[key] = text.split("\n")
        return split_cache[key]

    def comments_of(path: str, lines: list[str]) -> list[str | None]:
        key = source_key(path)
        if key not in comment_cache:
            py = _is_python(path)
            comment_cache[key] = _comment_texts(
                lines, path, _python_comments(sources[key]) if py else None
            )
        return comment_cache[key]

    def constants_of(path: str) -> tuple[frozenset[str], frozenset[str]] | None:
        key = source_key(path)
        if key not in constants_cache:
            constants_cache[key] = module_constants(sources[key]) if _is_python(path) else None
        return constants_cache[key]

    for f in matches:
        lines = lines_of(f.file_path)
        in_tests = is_test_path(f.file_path, root)
        line = (
            lines[f.line_start - 1] if lines is not None and 0 < f.line_start <= len(lines) else ""
        )

        if lines is not None and _inline_suppressed(lines, comments_of(f.file_path, lines), f):
            _bump(counts, REASON_INLINE)
            continue
        if in_tests and f.engine == "bandit" and f.pattern_id == "B101":
            _bump(counts, REASON_ASSERT_IN_TESTS)
            continue
        if line and lines is not None and _is_credential_label_candidate(f):
            if _is_dotenv_file(f.file_path):
                # Dotenv values are data, not code: suppress only a clear
                # placeholder, never a real value (see is_dotenv_placeholder).
                if line_is_dotenv_placeholder(line):
                    _bump(counts, REASON_CREDENTIAL_LABEL)
                    continue
            else:
                # Python: every line of the statement (a call's other arguments).
                s, e = statement_span(lines, f) if _is_python(f.file_path) else (f.line_start,) * 2
                if line_is_credential_label(line) and all(
                    _continuation_is_label(lines[i - 1]) for i in range(s + 1, e + 1)
                ):
                    _bump(counts, REASON_CREDENTIAL_LABEL)
                    continue
        if (
            line
            and f.pattern_id == "detect-secrets:Hex High Entropy String"
            and _hex_is_identifier(line)
        ):
            _bump(counts, REASON_OBJECT_ID)
            continue
        if lines is not None and f.pattern_id == "sql_injection_python_1":
            s, e = statement_span(lines, f)
            statement = "\n".join(lines[s - 1 : e])
            if _statement_is_constant(statement, constants_of(f.file_path)):
                _bump(counts, REASON_SQL_CONSTANT)
                continue
        if (
            in_tests
            and f.severity not in (VulnerabilitySeverity.LOW, VulnerabilitySeverity.INFO)
            and (not _is_provider_secret(f) or _is_bare_pem_header(f, lines))
        ):
            f.severity = VulnerabilitySeverity.LOW
            _bump(counts, REASON_TEST_DOWNGRADE)
        kept.append(f)
    return kept, counts
