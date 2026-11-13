"""Security Vulnerability Pattern Detection Service.

Advanced security vulnerability detection across multiple programming languages using
pattern matching, similarity analysis, and security-specific rule engines.
"""

from __future__ import annotations

import asyncio
import bisect
import logging
import re
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import regex

from services.scanner_errors import ScannerExecutionError, ScannerPartialRunError

if TYPE_CHECKING:
    from services.trivy_image_scanner import TrivyImageScanner

logger = logging.getLogger(__name__)

# Per regex, per file: findings beyond this many repeats add nothing a reader can
# act on, and each costs context extraction + a log line.
_MAX_MATCHES_PER_PATTERN = 200
# Per surrounding line, how much the context heuristics read.
_CONTEXT_LINE_CHARS = 2_000


def _newline_offsets(content: str) -> list[int]:
    """Offsets of every newline, so a match's line number is one bisect."""
    return [m.start() for m in re.finditer("\n", content)]


# ---------------------------------------------------------------------------
# Main-equivalent fallback for the bounded rewrites.
#
# The detector's unbounded .* / [^)]* spans were rewritten as bounded
# ({0,300}) linear spans because the originals are quadratic (ReDoS) on
# adversarial input. Within 300 chars they match what main matched; beyond it
# they do not (os.system('<400 chars>' + user)). So every bounded rewrite
# keeps main's ORIGINAL pattern here, and whenever the content is longer than
# the bound the original also runs -- through the regex module with a
# per-call timeout and a per-file budget. A timeout or an exhausted budget is
# recorded as a degraded reason: the scan is never reported clean on a check
# that did not finish.
# ---------------------------------------------------------------------------
_BOUNDED_SPAN_CHARS = 300
_FALLBACK_CALL_TIMEOUT_S = 0.05
_FALLBACK_FILE_BUDGET_S = 0.75

# bounded pattern (as in _load_security_patterns) -> main's original pattern.
_UNBOUNDED_ORIGINALS: dict[str, str] = {
    # command_injection_java_1[0]
    "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\((?=[^)]{0,300}\\))(?>(?:[^)\\n]{0,300}\\n)*)[^)\\n]{0,300}?\\+": "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\([^)]*\\+.*\\)",
    # command_injection_java_1[1]
    "ProcessBuilder\\s*\\((?=[^)]{0,300}\\))(?>(?:[^)\\n]{0,300}\\n)*)[^)\\n]{0,300}?\\+": "ProcessBuilder\\s*\\([^)]*\\+.*\\)",
    # command_injection_python_1[0]
    "os\\.system\\s*\\((?=[^)]{0,300}\\))(?>(?:[^)\\n]{0,300}\\n)*)[^)\\n]{0,300}?\\+": "os\\.system\\s*\\([^)]*\\+.*\\)",
    # command_injection_python_1[1]
    "subprocess\\.call\\s*\\((?>[^)]{0,300}?shell\\s*=\\s*True)(?>[^)]{0,300}?\\+)": "subprocess\\.call\\s*\\([^)]*shell\\s*=\\s*True[^)]*\\+",
    # command_injection_python_1[2]
    "subprocess\\.run\\s*\\((?>[^)]{0,300}?shell\\s*=\\s*True)(?>[^)]{0,300}?\\+)": "subprocess\\.run\\s*\\([^)]*shell\\s*=\\s*True[^)]*\\+",
    # command_injection_python_1[3]
    "subprocess\\.(?:run|call|Popen)\\s*\\(\\s*[^\"'\\s)](?>[^)]{0,300}?shell\\s*=\\s*True)": "subprocess\\.(?:run|call|Popen)\\s*\\(\\s*[^\"'\\s)][^)]*shell\\s*=\\s*True",
    # insecure_deserialization_java_1[1]
    "ObjectInputStream.{0,300}read": "ObjectInputStream.*read",
    # insecure_deserialization_java_1[2]
    "XMLDecoder.{0,300}read": "XMLDecoder.*read",
    # ldap_injection_generic_1[0]
    "LdapName(?>.{0,300}?new)(?>.{0,300}?\\+)|DirContext(?>.{0,300}?search)(?>.{0,300}?\\+)": "LdapName.*new.*\\+|DirContext.*search.*\\+",
    # ldap_injection_generic_1[1]
    "FilterEncoder|LdapContext.{0,300}search": "FilterEncoder|LdapContext.*search",
    # log4shell_cve_2021_44228_1[1]
    "log4j.{0,300}2\\.(0-16|16\\.\\d+)": "log4j.*2\\.(0-16|16\\.\\d+)",
    # log4shell_cve_2021_44228_1[2]
    "LoggerFactory\\.getLogger\\(.{0,300}\\)\\s*\\.(?:debug|info|warn|error)\\s*\\(": "LoggerFactory\\.getLogger\\(.*\\)\\s*\\.(?:debug|info|warn|error)\\s*\\(",
    # path_traversal_generic_1[0]
    "open\\s*\\(.{0,300}[\"\\'][\\.]\\.[/\\\\]": "open\\s*\\(.*[\"\\'][\\.]\\.[/\\\\]",
    # path_traversal_generic_1[1]
    "File\\s*\\(.{0,300}[\"\\'][\\.]\\.[/\\\\]": "File\\s*\\(.*[\"\\'][\\.]\\.[/\\\\]",
    # path_traversal_generic_1[2]
    "readFile.{0,300}\\+|readFile.{0,300}\\{|readFile.{0,300}template": "readFile.*\\+|readFile.*\\{|readFile.*template",
    # spring4shell_cve_2022_22965_1[1]
    "WebDataBinder.{0,300}bindingResult": "WebDataBinder.*bindingResult",
    # spring4shell_cve_2022_22965_1[3]
    "@Controller|@RestController.{0,300}@RequestMapping": "@Controller|@RestController.*@RequestMapping",
    # sql_injection_java_1[0]
    "Statement.{0,300}createStatement\\(\\)": "Statement.*createStatement\\(\\)",
    # sql_injection_java_1[1]
    "\\.executeQuery\\s*\\(\\s*[\"'](?=[^\"']{0,300}[\"'])(?>(?:[^\"'\\n]{0,300}\\n)*)[^\"'\\n]{0,300}?\\+": "\\.executeQuery\\s*\\(\\s*[\"\\'][^\"\\']*\\+.*[\"\\']",
    # sql_injection_python_1[2]
    "\\.execute\\s*\\(\\s*f[\"'](?>[^\"'{]{0,300}(?:\\{\\}[^\"'{]{0,300})*)\\{(?!\\})[^}]{1,300}}[^\"']{0,300}[\"']": "\\.execute\\s*\\(\\s*f[\"\\'][^\"\\']*{[^}]+}[^\"\\']*[\"\\']",
    # sql_injection_python_1[4]
    "\\.execute\\s*\\(\\s*[\"\\'](?>[^\"\\']{0,300}?%[sd])[^\"\\']{0,300}[\"\\']\\s*%": "\\.execute\\s*\\(\\s*[\"\\'][^\"\\']*%[sd][^\"\\']*[\"\\']\\s*%",
    # xml_injection_generic_1[1]
    "setFeature.{0,300}XMLConstants\\.ACCESS_EXTERNAL": "setFeature.*XMLConstants\\.ACCESS_EXTERNAL",
    # xml_injection_generic_1[2]
    "XXE|DOCTYPE.{0,300}ENTITY": "XXE|DOCTYPE.*ENTITY",
    # xss_javascript_1[0]
    "\\.innerHTML\\s*=\\s*(?>[^;]{0,300}?(?:location|document\\.URL|window\\.location))": "\\.innerHTML\\s*=\\s*[^;]*(?:location|document\\.URL|window\\.location)",
    # xss_javascript_1[1]
    "\\.innerHTML\\s*=\\s*(?>.{0,300}?\\+).{0,300}": "\\.innerHTML\\s*=\\s*.*\\+.*",
    # xss_python_1[0]
    "render_template_string\\s*\\((?>[^)]{0,300}?request\\.)": "render_template_string\\s*\\([^)]*request\\.",
    # xss_python_1[1]
    "Template\\([^)]{0,300}\\)\\.render\\((?>[^)]{0,300}?request\\.)": "Template\\([^)]*\\)\\.render\\([^)]*request\\.",
}


@dataclass
class _FallbackBudget:
    """Per-file time budget for the main-equivalent fallback checks."""

    file_path: str
    deadline: float
    reasons: list[str] = field(default_factory=list)
    exhausted: bool = False

    @classmethod
    def for_file(cls, file_path: str) -> _FallbackBudget:
        return cls(file_path=file_path, deadline=time.monotonic() + _FALLBACK_FILE_BUDGET_S)


def _longest_line(lines: list[str]) -> tuple[int, int]:
    """(1-based line number, length) of the longest line."""
    best = max(range(len(lines)), key=lambda i: len(lines[i]), default=0)
    return best + 1, (len(lines[best]) if lines else 0)


# ============================================================================
# Stub types for monolith dependencies that are not yet extracted.
# These provide minimal interfaces so the detector can function standalone.
# TODO: Replace with proper shared library imports when available.
# ============================================================================


class EntityType(StrEnum):
    """Minimal stub for core_models.EntityType."""

    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    MODULE = "module"
    VARIABLE = "variable"
    IMPORT = "import"
    INTERFACE = "interface"
    ENUM = "enum"


@dataclass
class CoreCodeEntity:
    """Minimal stub for core_models.CoreCodeEntity."""

    id: str
    name: str
    type: EntityType
    language: str
    file_path: str
    line_number: int
    end_line_number: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    visibility: str | None = None
    code_snippet: str | None = None
    docstring: str | None = None
    source_code: str | None = None


@dataclass
class EntityRelation:
    """Minimal stub for core_models.EntityRelation."""

    source_id: str
    target_id: str
    relation_type: str
    file_path: str | None = None
    line_number: int | None = None


class ParserType(StrEnum):
    """Minimal stub for languages.base.ParserType."""

    TREE_SITTER = "tree_sitter"
    REGEX_FALLBACK = "regex_fallback"
    AST_PARSER = "ast_parser"


@dataclass
class ParseResult:
    """Minimal stub for languages.base.ParseResult."""

    success: bool
    file_path: str
    language: str
    parser_used: ParserType
    ast: Any = None
    entities: list[Any] = field(default_factory=list)
    relationships: list[Any] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


class FileService:
    """Minimal stub for file_service.FileService.

    TODO: Replace with proper shared file service when available.
    """

    def __init__(
        self,
        base_path: Path | None = None,
        default_encoding: str = "utf-8",
        logger_instance: Any = None,
    ):
        self.base_path = base_path
        self.default_encoding = default_encoding

    def read_file(self, file_path: str) -> str:
        """Read file content."""
        with open(file_path, encoding=self.default_encoding) as f:
            return f.read()


# ============================================================================
# End of stubs
# ============================================================================


class ScanEngine(StrEnum):
    """The engine that produced a finding (R216).

    Every ``VulnerabilityMatch`` carries one of these in ``engine`` so a consumer
    never has to infer the producer from the rule-id shape (e.g. "AVD-* means
    IaC"). ``pattern`` is the in-process regex/AST rule set; the rest are the
    external CLIs the container-scan path runs.
    """

    PATTERN = "pattern"
    BANDIT = "bandit"
    SEMGREP = "semgrep"
    DETECT_SECRETS = "detect-secrets"  # pragma: allowlist secret (engine name, not a secret)
    TRIVY_IAC = "trivy-iac"
    #: OS packages of the Dockerfile base image (`trivy image`). Distinct from
    #: trivy-iac: that one reads the Dockerfile text, this one scans the image
    #: the Dockerfile builds FROM.
    TRIVY_IMAGE = "trivy-image"


#: Every engine the container-scan path runs, in run order. ``engine_status``
#: always carries exactly these keys, so a consumer checking "any engine not ok"
#: can never pass vacuously on a missing key.
SCAN_ENGINES: tuple[ScanEngine, ...] = tuple(ScanEngine)

ENGINE_OK = "ok"
ENGINE_DEGRADED = "degraded"
ENGINE_FAILED = "failed"


def _engine_status(status: str, reason: str | None = None) -> dict[str, str | None]:
    return {"status": status, "reason": reason}


def all_engines_failed(reason: str) -> dict[str, dict[str, str | None]]:
    """``engine_status`` for a scan that examined nothing: no engine is ok."""
    return {str(e): _engine_status(ENGINE_FAILED, reason) for e in SCAN_ENGINES}


class VulnerabilityType(StrEnum):
    """Types of security vulnerabilities."""

    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    INTEGER_OVERFLOW = "integer_overflow"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INSECURE_RANDOM = "insecure_random"
    DESERIALIZATION = "unsafe_deserialization"
    RACE_CONDITION = "race_condition"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CSRF = "cross_site_request_forgery"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    REGEX_DOS = "regex_denial_of_service"
    TIMING_ATTACK = "timing_attack"
    LOG4J_RCE = "log4j_remote_code_execution"
    SPRING_RCE = "spring_remote_code_execution"
    #: A known CVE in a package the code ships without importing it — an OS
    #: package of the Dockerfile base image (produced by the trivy-image
    #: engine). Kept separate from the source-code types above so a base-image
    #: CVE never merges with a code finding on the same file+line.
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"


class VulnerabilitySeverity(StrEnum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityConfidence(StrEnum):
    """Confidence levels for vulnerability detection."""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


@dataclass
class VulnerabilityPattern:
    """Security vulnerability pattern definition for detection."""

    id: str
    name: str
    vulnerability_type: VulnerabilityType
    severity: VulnerabilitySeverity
    description: str
    language: str
    code_patterns: list[str] = field(default_factory=list)
    ast_patterns: list[str] = field(default_factory=list)
    api_patterns: list[str] = field(default_factory=list)
    required_imports: list[str] = field(default_factory=list)
    forbidden_mitigations: list[str] = field(default_factory=list)
    required_context: dict[str, Any] = field(default_factory=dict)
    cwe_ids: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class VulnerabilityMatch:
    """A detected security vulnerability."""

    id: str
    vulnerability_type: VulnerabilityType
    severity: VulnerabilitySeverity
    confidence: VulnerabilityConfidence
    file_path: str
    language: str
    line_start: int
    line_end: int
    function_name: str | None = None
    class_name: str | None = None
    pattern_id: str = ""
    title: str = ""
    description: str = ""
    code_snippet: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    remediation_advice: str = ""
    resolve_suggestions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    context_evidence: dict[str, Any] = field(default_factory=dict)
    false_positive_likelihood: float = 0.0
    #: Producing engine (a ``ScanEngine`` value), set by the producer itself.
    engine: str = ""
    #: Structured base-image CVE context, set by trivy-image and empty for every
    #: other engine (whose findings are not package CVEs). Consumers read these
    #: fields instead of parsing the free-text ``description``.
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    fix_available: bool = False
    image_ref: str = ""


@dataclass
class SecurityAnalysisResult:
    """Result of security vulnerability analysis."""

    total_files_analyzed: int
    total_vulnerabilities_found: int
    analysis_time_seconds: float
    # Degradation signals: the scan ran but could not examine everything it was
    # asked to (files that failed to parse, or an augmentation tool that errored).
    # A degraded scan with zero findings is NOT trustworthy as "clean".
    files_failed_to_parse: int = 0
    scan_degraded: bool = False
    # One entry per cause of ``scan_degraded`` (engine not installed, engine
    # failed, ...), so a caller can say WHY the scan is not trustworthy.
    degraded_reasons: list[str] = field(default_factory=list)
    # Per-engine outcome, keyed by every ``ScanEngine`` value:
    # {"status": "ok"|"degraded"|"failed", "reason": str|None}.
    engine_status: dict[str, dict[str, str | None]] = field(default_factory=dict)
    # Per-Dockerfile base-image coverage rows
    # ({"ref", "dockerfile", "line", "status", "error"}), one per FROM
    # reference. Empty when there is no Dockerfile or trivy-image never ran;
    # a row with status "unresolved" is a coverage gap, never clean.
    base_images: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities_by_type: dict[VulnerabilityType, list[VulnerabilityMatch]] = field(
        default_factory=dict
    )
    vulnerabilities_by_severity: dict[VulnerabilitySeverity, list[VulnerabilityMatch]] = field(
        default_factory=dict
    )
    vulnerabilities_by_confidence: dict[VulnerabilityConfidence, list[VulnerabilityMatch]] = field(
        default_factory=dict
    )
    language_distribution: dict[str, int] = field(default_factory=dict)
    vulnerabilities_by_language: dict[str, list[VulnerabilityMatch]] = field(default_factory=dict)
    overall_risk_score: float = 0.0
    critical_issues_count: int = 0
    high_severity_count: int = 0
    most_common_vulnerability: VulnerabilityType | None = None
    security_hotspots: list[str] = field(default_factory=list)
    priority_fixes: list[VulnerabilityMatch] = field(default_factory=list)
    security_improvements: list[str] = field(default_factory=list)
    # Findings the false-positive filters removed (or, for
    # ``test_path_downgraded``, lowered to LOW), counted by reason — see
    # ``services.finding_filters``. Never silent: every action is counted here.
    suppressed_findings: dict[str, int] = field(default_factory=dict)


@dataclass
class PartialAnalysisState:
    """Caller-held accumulator so partial findings survive a scan timeout.

    ``analyze_security_vulnerabilities`` runs under an overall wall-clock
    deadline (``asyncio.wait_for`` in the router). When that deadline fires it
    cancels the coroutine, unwinding every local — so the vulnerabilities the
    already-completed engines found would be lost. By accumulating into an
    instance the *caller* holds, whatever was found before cancellation stays
    readable, and the timeout handler can rebuild a degraded-but-real result
    from it instead of discarding everything (fake "F, 0 vulns" on a repo that
    in fact has findings).

    The scan engines run sequentially with per-tool timeouts (120-180s) larger
    than the overall budget (~60s), so a timeout typically lands after some
    engines completed and mid-way through another — exactly the case where
    real partial findings exist.
    """

    include_low_confidence: bool = True
    parsed_files: list[ParseResult] = field(default_factory=list)
    regex_matches: list[VulnerabilityMatch] = field(default_factory=list)
    external_matches: list[VulnerabilityMatch] = field(default_factory=list)
    files_failed_to_parse: int = 0
    augmentation_degraded: bool = False
    degraded_reasons: list[str] = field(default_factory=list)
    # Filled per engine as each one finishes; an engine absent at deadline time
    # did not complete and is reported failed by ``result_from_partial``.
    engine_status: dict[str, dict[str, str | None]] = field(default_factory=dict)
    # Base-image coverage rows, appended by the trivy-image engine as soon as
    # the FROM references are known. Survives cancellation mid-image.
    base_images: list[dict[str, Any]] = field(default_factory=list)


class SecurityVulnerabilityDetector:
    """Advanced security vulnerability detection across multiple languages."""

    def __init__(self, file_service: FileService | None = None):
        """Initialize the security detector.

        Args:
            file_service: File service for reading code files
        """
        self.file_service = file_service or FileService()
        self.patterns = self._load_security_patterns()
        self.severity_scores = {
            VulnerabilitySeverity.CRITICAL: 9.5,
            VulnerabilitySeverity.HIGH: 8.0,
            VulnerabilitySeverity.MEDIUM: 5.5,
            VulnerabilitySeverity.LOW: 2.0,
            VulnerabilitySeverity.INFO: 0.0,
        }
        # Real source-SAST engines. Imported lazily to avoid a circular import
        # (the scanner modules import VulnerabilityMatch from this module). When
        # the CLIs are absent, is_available() is False and the regex engine is
        # used unchanged (graceful fallback).
        from services.bandit_scanner import BanditScanner
        from services.iac_scanner import IaCScanner
        from services.secrets_scanner import SecretsScanner
        from services.semgrep_scanner import SemgrepScanner
        from services.trivy_image_scanner import TrivyImageScanner

        self._bandit = BanditScanner()
        self._secrets = SecretsScanner()
        self._semgrep = SemgrepScanner()
        self._iac = IaCScanner()
        self._image = TrivyImageScanner()
        logger.info(
            "Security vulnerability detector initialized "
            f"(bandit={self._bandit.is_available()}, "
            f"detect-secrets={self._secrets.is_available()}, "
            f"semgrep={self._semgrep.is_available()}, "
            f"iac={self._iac.is_available()}, "
            f"base_image={self._image.is_available()})"
        )

    def _load_security_patterns(self) -> list[VulnerabilityPattern]:
        """Load security vulnerability patterns for different languages."""
        patterns = []
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="sql_injection_python_1",
                    name="SQL Injection via String Concatenation",
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                    severity=VulnerabilitySeverity.HIGH,
                    description="Direct string concatenation in SQL queries without parameterization",
                    language="python",
                    code_patterns=[
                        # String concatenation into a query on ANY cursor receiver, string first
                        # (cur./db./conn./cursor.execute("..." + var)). Generalised from the old
                        # cursor-literal prefix that ALSO required a quote on both sides of `+`,
                        # so it missed the common `"..." + var` form (the live-fire miss).
                        "\\.execute\\s*\\(\\s*[\"\\'][^\"\\']*[\"\\']\\s*\\+",
                        # Concatenation with the variable first (cur.execute(var + "...")).
                        "\\.execute\\s*\\(\\s*\\w+\\s*\\+\\s*[\"\\']",
                        # f-string interpolation into a query (cur.execute(f"... {var} ...")).
                        "\\.execute\\s*\\(\\s*f[\"'](?>[^\"'{]{0,300}(?:\\{\\}[^\"'{]{0,300})*)\\{(?!\\})[^}]{1,300}}[^\"']{0,300}[\"']",
                        # str.format()-built query (cur.execute("... {} ...".format(var))).
                        "\\.execute\\s*\\(\\s*[\"\\'][^\"\\']*[\"\\']\\.format\\s*\\(",
                        # Old-style %-format OPERATOR applied to the query string
                        # (cur.execute("...%s..." % var)). The trailing `%` AFTER the closing
                        # quote is what makes it unsafe. The safe parameterized form
                        # cur.execute("...%s...", (var,)) has a comma there, not a `%`, so it is
                        # NOT matched -- this replaces the inverted pattern that flagged the
                        # safe %s placeholder as HIGH.
                        "\\.execute\\s*\\(\\s*[\"\\'](?>[^\"\\']{0,300}?%[sd])[^\"\\']{0,300}[\"\\']\\s*%",
                    ],
                    api_patterns=["execute", "executemany"],
                    cwe_ids=["CWE-89"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2019-9193", "CVE-2020-1938"],
                ),
                VulnerabilityPattern(
                    id="sql_injection_java_1",
                    name="SQL Injection via Statement",
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                    severity=VulnerabilitySeverity.HIGH,
                    description="Use of Statement instead of PreparedStatement with user input",
                    language="java",
                    code_patterns=[
                        "Statement.{0,300}createStatement\\(\\)",
                        "\\.executeQuery\\s*\\(\\s*[\"'](?=[^\"']{0,300}[\"'])(?>(?:[^\"'\\n]{0,300}\\n)*)[^\"'\\n]{0,300}?\\+",
                    ],
                    api_patterns=["createStatement", "executeQuery"],
                    cwe_ids=["CWE-89"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2019-9193", "CVE-2021-22945"],
                ),
            ]
        )
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="xss_javascript_1",
                    name="DOM XSS via innerHTML",
                    vulnerability_type=VulnerabilityType.XSS,
                    severity=VulnerabilitySeverity.MEDIUM,
                    description="Direct assignment to innerHTML without sanitization",
                    language="javascript",
                    code_patterns=[
                        "\\.innerHTML\\s*=\\s*(?>[^;]{0,300}?(?:location|document\\.URL|window\\.location))",
                        "\\.innerHTML\\s*=\\s*(?>.{0,300}?\\+).{0,300}",
                    ],
                    cwe_ids=["CWE-79"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2020-5410", "CVE-2021-3129", "CVE-2022-0536"],
                ),
                VulnerabilityPattern(
                    id="xss_python_1",
                    name="Template Injection",
                    vulnerability_type=VulnerabilityType.XSS,
                    severity=VulnerabilitySeverity.MEDIUM,
                    description="Unsafe template rendering without proper escaping",
                    language="python",
                    code_patterns=[
                        "render_template_string\\s*\\((?>[^)]{0,300}?request\\.)",
                        "Template\\([^)]{0,300}\\)\\.render\\((?>[^)]{0,300}?request\\.)",
                    ],
                    cwe_ids=["CWE-79"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2019-9193", "CVE-2021-3129"],
                ),
            ]
        )
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="command_injection_python_1",
                    name="Command Injection via os.system",
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="Use of os.system with user-controlled input",
                    language="python",
                    code_patterns=[
                        "os\\.system\\s*\\((?=[^)]{0,300}\\))(?>(?:[^)\\n]{0,300}\\n)*)[^)\\n]{0,300}?\\+",
                        "subprocess\\.call\\s*\\((?>[^)]{0,300}?shell\\s*=\\s*True)(?>[^)]{0,300}?\\+)",
                        "subprocess\\.run\\s*\\((?>[^)]{0,300}?shell\\s*=\\s*True)(?>[^)]{0,300}?\\+)",
                        # shell=True with a non-string-literal first arg
                        # (subprocess.run(cmd, shell=True)) -- a variable/f-string command under a
                        # shell is injectable even without explicit `+`. A string-literal command
                        # (starts with a quote) is not flagged.
                        "subprocess\\.(?:run|call|Popen)\\s*\\(\\s*[^\"'\\s)](?>[^)]{0,300}?shell\\s*=\\s*True)",
                    ],
                    api_patterns=["os.system", "subprocess.call", "subprocess.run"],
                    cwe_ids=["CWE-78"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2019-1010317", "CVE-2020-1938"],
                ),
                VulnerabilityPattern(
                    id="command_injection_java_1",
                    name="Command Injection via Runtime.exec",
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="Use of Runtime.exec with concatenated user input",
                    language="java",
                    code_patterns=[
                        "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\((?=[^)]{0,300}\\))(?>(?:[^)\\n]{0,300}\\n)*)[^)\\n]{0,300}?\\+",
                        "ProcessBuilder\\s*\\((?=[^)]{0,300}\\))(?>(?:[^)\\n]{0,300}\\n)*)[^)\\n]{0,300}?\\+",
                    ],
                    api_patterns=["Runtime.exec", "ProcessBuilder"],
                    cwe_ids=["CWE-78"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2015-4852", "CVE-2016-3720"],
                ),
            ]
        )
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="hardcoded_password_1",
                    name="Hardcoded Password",
                    vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS,
                    severity=VulnerabilitySeverity.HIGH,
                    description="Hardcoded passwords or API keys in source code",
                    language="any",
                    code_patterns=[
                        "password\\s*=\\s*[\"\\'][^\"\\']{8,}[\"\\']",
                        "api_key\\s*=\\s*[\"\\'][^\"\\']{16,}[\"\\']",
                        "secret\\s*=\\s*[\"\\'][^\"\\']{8,}[\"\\']",
                        "token\\s*=\\s*[\"\\'][^\"\\']{16,}[\"\\']",
                        # Credential-named identifier with a long literal, where the
                        # keyword is NOT the last word of the name — e.g.
                        # AWS_SECRET_ACCESS_KEY = "...", db_password_prod = "...".
                        # The four forms above require `=` right after the keyword
                        # and missed every such name.
                        # LINEAR by construction (an unbounded `\w*` here was
                        # quadratic: "secret"*33334 took 40 s): the keyword may
                        # not start inside an alphanumeric run (lookbehind), the
                        # name tail is bounded, and nothing crosses a line.
                        "(?<![A-Za-z0-9])"
                        "(?:secret|passw(?:or)?d|api_?key|access_?key|private_?key|auth_?token)"
                        "\\w{0,40}[ \\t]*[:=][ \\t]*[\"\\'][^\"\\'\\s]{16,512}[\"\\']",
                        # AWS access key id literal.
                        "\\bA(?:KIA|SIA)[0-9A-Z]{16}\\b",
                        # Provider token literals (all bounded, linear). Each is a
                        # live credential by its shape alone, whatever the name.
                        # Slack bot/user/app/refresh tokens.
                        "\\bxox[baprs]-[0-9A-Za-z-]{10,200}",
                        # PEM private key header (RSA/EC/DSA/OPENSSH/ENCRYPTED/...).
                        "-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY-----",
                        # GitHub personal/OAuth/server/user/refresh tokens.
                        "\\b(?-i:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})",
                        # Stripe live secret / restricted keys.
                        "\\b(?-i:[sr]k_live_[0-9A-Za-z]{16,99})",
                        # Google API key.
                        "\\b(?-i:AIza[0-9A-Za-z_\\-]{35})",
                    ],
                    cwe_ids=["CWE-798"],
                    owasp_categories=["A07:2021 – Identification and Authentication Failures"],
                    references=["CVE-2021-3807", "CVE-2021-43565"],
                )
            ]
        )
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="weak_crypto_python_1",
                    name="Weak Cryptographic Algorithm",
                    vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                    severity=VulnerabilitySeverity.MEDIUM,
                    description="Use of weak or deprecated cryptographic algorithms",
                    language="python",
                    code_patterns=[
                        "hashlib\\.md5\\s*\\(",
                        "hashlib\\.sha1\\s*\\(",
                        "Crypto\\.Cipher\\.DES",
                        "Crypto\\.Cipher\\.ARC4",
                    ],
                    api_patterns=["hashlib.md5", "hashlib.sha1"],
                    cwe_ids=["CWE-327"],
                    owasp_categories=["A02:2021 – Cryptographic Failures"],
                    references=["CVE-2013-5915", "CVE-2012-2459"],
                )
            ]
        )
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="buffer_overflow_c_1",
                    name="Buffer Overflow via strcpy",
                    vulnerability_type=VulnerabilityType.BUFFER_OVERFLOW,
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="Use of unsafe string functions that can cause buffer overflows",
                    language="cpp",
                    code_patterns=[
                        "strcpy\\s*\\(",
                        "strcat\\s*\\(",
                        "sprintf\\s*\\(",
                        "gets\\s*\\(",
                    ],
                    api_patterns=["strcpy", "strcat", "sprint", "gets"],
                    cwe_ids=["CWE-120"],
                    owasp_categories=["A06:2021 – Vulnerable and Outdated Components"],
                    references=["CVE-2014-1732", "CVE-2013-4152"],
                )
            ]
        )
        # Add CVE-specific patterns
        patterns.extend(
            [
                VulnerabilityPattern(
                    id="log4shell_cve_2021_44228_1",
                    name="Log4Shell (CVE-2021-44228) - Remote Code Execution",
                    vulnerability_type=VulnerabilityType.LOG4J_RCE,
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="Apache Log4j2 before 2.17.0 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints",
                    language="java",
                    code_patterns=[
                        "import\\s+org\\.apache\\.logging\\.log4j",
                        "log4j.{0,300}2\\.(0-16|16\\.\\d+)",
                        "LoggerFactory\\.getLogger\\(.{0,300}\\)\\s*\\.(?:debug|info|warn|error)\\s*\\(",
                    ],
                    api_patterns=["org.apache.logging.log4j"],
                    cwe_ids=["CWE-94", "CWE-400"],
                    owasp_categories=["A06:2021 – Vulnerable and Outdated Components"],
                    references=["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                ),
                VulnerabilityPattern(
                    id="spring4shell_cve_2022_22965_1",
                    name="Spring4Shell (CVE-2022-22965) - Remote Code Execution",
                    vulnerability_type=VulnerabilityType.SPRING_RCE,
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="Spring Framework supports writing to WebDataBinder targets by using the property name prefix in HTTP requests. Vulnerability in parameter binding.",
                    language="java",
                    code_patterns=[
                        "org\\.springframework\\.web\\.bind",
                        "WebDataBinder.{0,300}bindingResult",
                        "ModelAttributeMethodProcessor",
                        "@Controller|@RestController.{0,300}@RequestMapping",
                    ],
                    api_patterns=["WebDataBinder", "DataBinder"],
                    cwe_ids=["CWE-95"],
                    owasp_categories=["A06:2021 – Vulnerable and Outdated Components"],
                    references=["CVE-2022-22965", "CVE-2022-22947"],
                ),
                VulnerabilityPattern(
                    id="insecure_deserialization_java_1",
                    name="Unsafe Deserialization in Java",
                    vulnerability_type=VulnerabilityType.DESERIALIZATION,
                    severity=VulnerabilitySeverity.HIGH,
                    description="Unsafe deserialization of untrusted data can lead to remote code execution",
                    language="java",
                    code_patterns=[
                        "readObject\\s*\\(\\)",
                        "ObjectInputStream.{0,300}read",
                        "XMLDecoder.{0,300}read",
                    ],
                    api_patterns=["readObject", "ObjectInputStream"],
                    cwe_ids=["CWE-502"],
                    owasp_categories=["A08:2021 – Software and Data Integrity Failures"],
                    references=["CVE-2015-4852", "CVE-2015-6420"],
                ),
                VulnerabilityPattern(
                    id="path_traversal_generic_1",
                    name="Path Traversal Vulnerability",
                    vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                    severity=VulnerabilitySeverity.HIGH,
                    description="File access using user-controlled paths without proper validation",
                    language="any",
                    code_patterns=[
                        "open\\s*\\(.{0,300}[\"\\'][\\.]\\.[/\\\\]",
                        "File\\s*\\(.{0,300}[\"\\'][\\.]\\.[/\\\\]",
                        "readFile.{0,300}\\+|readFile.{0,300}\\{|readFile.{0,300}template",
                    ],
                    cwe_ids=["CWE-22"],
                    owasp_categories=["A01:2021 – Broken Access Control"],
                    references=["CVE-2021-22911", "CVE-2022-24999"],
                ),
                VulnerabilityPattern(
                    id="ldap_injection_generic_1",
                    name="LDAP Injection Vulnerability",
                    vulnerability_type=VulnerabilityType.LDAP_INJECTION,
                    severity=VulnerabilitySeverity.HIGH,
                    description="LDAP query injection through unsanitized user input",
                    language="java",
                    code_patterns=[
                        "LdapName(?>.{0,300}?new)(?>.{0,300}?\\+)|DirContext(?>.{0,300}?search)(?>.{0,300}?\\+)",
                        "FilterEncoder|LdapContext.{0,300}search",
                    ],
                    cwe_ids=["CWE-90"],
                    owasp_categories=["A03:2021 – Injection"],
                    references=["CVE-2021-27906"],
                ),
                VulnerabilityPattern(
                    id="xml_injection_generic_1",
                    name="XML External Entity (XXE) Injection",
                    vulnerability_type=VulnerabilityType.XML_INJECTION,
                    severity=VulnerabilitySeverity.HIGH,
                    description="XML parsing with external entity resolution enabled",
                    language="java",
                    code_patterns=[
                        "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory",
                        "setFeature.{0,300}XMLConstants\\.ACCESS_EXTERNAL",
                        "XXE|DOCTYPE.{0,300}ENTITY",
                    ],
                    cwe_ids=["CWE-611"],
                    owasp_categories=["A05:2021 – Security Misconfiguration"],
                    references=["CVE-2013-2156", "CVE-2020-8949"],
                ),
            ]
        )
        return patterns

    async def analyze_security_vulnerabilities(
        self,
        file_paths: Sequence[str | Path],
        include_low_confidence: bool = True,
        max_files: int | None = None,
        *,
        partial: PartialAnalysisState | None = None,
        deadline: float | None = None,
    ) -> SecurityAnalysisResult:
        """Analyze code for security vulnerabilities.

        Args:
            file_paths: List of file paths to analyze
            include_low_confidence: Whether to include low confidence findings
            max_files: Maximum number of files to analyze

        Returns:
            Comprehensive security analysis result
        """
        start_time = datetime.now(UTC)
        if max_files and len(file_paths) > max_files:
            file_paths = file_paths[:max_files]
            logger.info(f"Limited analysis to {max_files} files for performance")
        logger.info(f"Starting security analysis on {len(file_paths)} files")
        if partial is not None:
            partial.include_low_confidence = include_low_confidence
        # Accumulate into the caller-held ``partial`` (sharing the list refs) so
        # an overall-deadline timeout that cancels this coroutine can still
        # recover the files parsed and engines completed so far.
        parsed_files = partial.parsed_files if partial is not None else []
        files_failed_to_parse = 0
        for file_path in file_paths:
            parse_result = None
            try:
                parse_result = await self._parse_file_for_security(Path(file_path))
            except (
                FileNotFoundError,
                PermissionError,
                UnicodeDecodeError,
                ValueError,
                ConnectionError,
                ConnectionRefusedError,
                OSError,
                # Pathologically nested source overflows the parser: the file
                # was not examined, which counts toward degradation below.
                MemoryError,
                RecursionError,
            ) as e:
                logger.warning(f"Failed to parse {file_path}: {e}")
            if parse_result:
                parsed_files.append(parse_result)
            else:
                # None (read failure) or an exception above: the file could not
                # be examined. Counts toward degradation so a partial scan is
                # not reported as fully clean.
                files_failed_to_parse += 1
                if partial is not None:
                    partial.files_failed_to_parse = files_failed_to_parse
        if not parsed_files:
            # Files were requested but none could be examined → the scan saw
            # nothing. Flag degraded so a zero-finding result is not read as clean.
            logger.warning("No files successfully parsed for security analysis")
            return SecurityAnalysisResult(
                total_files_analyzed=0,
                total_vulnerabilities_found=0,
                analysis_time_seconds=0.0,
                files_failed_to_parse=files_failed_to_parse,
                # Zero files examined is ALWAYS degraded — whether files were
                # requested and all failed to parse, or none were passed at all.
                # A zero-coverage scan must never be reported as clean.
                scan_degraded=True,
                degraded_reasons=["no files could be examined"],
                engine_status=all_engines_failed("no files could be examined"),
            )
        degraded_reasons: list[str] = partial.degraded_reasons if partial is not None else []
        n_reasons_before = len(degraded_reasons)
        engine_status: dict[str, dict[str, str | None]] = (
            partial.engine_status if partial is not None else {}
        )
        pattern_crashed = False
        try:
            regex_vulns = await self._detect_vulnerabilities(
                parsed_files, include_low_confidence, degraded_reasons
            )
        except Exception as e:
            # The in-process engine is an engine like the others: a crash part-way
            # (bad regex, unexpected input) means its findings are missing. It is
            # FAILED — never ok, and never a reason to lose the external engines.
            logger.exception("pattern engine crashed")
            regex_vulns = []
            pattern_crashed = True
            degraded_reasons.append(f"engine pattern crashed: {type(e).__name__}: {e}")
        # The pattern engine (which also does the parse step) only examined the
        # files that parsed: a file it could not parse is a partial run too.
        # (The scan-level "N file(s) could not be parsed" reason is added below.)
        pattern_reasons = list(degraded_reasons[n_reasons_before:])
        if files_failed_to_parse:
            pattern_reasons.append(
                f"{files_failed_to_parse} file(s) could not be parsed and were not examined"
            )
        # A long-span check that timed out / ran out of budget, an unreadable
        # file, a crash: findings may be missing, so the scan is degraded.
        detector_degraded = len(degraded_reasons) > n_reasons_before
        pattern_reason = "; ".join(pattern_reasons)
        if pattern_crashed:
            engine_status[ScanEngine.PATTERN] = _engine_status(ENGINE_FAILED, pattern_reason)
        elif pattern_reasons:
            engine_status[ScanEngine.PATTERN] = _engine_status(ENGINE_DEGRADED, pattern_reason)
        else:
            engine_status[ScanEngine.PATTERN] = _engine_status(ENGINE_OK)
        if partial is not None:
            partial.regex_matches = regex_vulns

        # Augment the regex engine with real SAST/secret/IaC engines (bandit =
        # Python, semgrep = multi-language, detect-secrets = secrets, trivy
        # config = IaC/misconfiguration). Absent CLIs -> empty list -> regex
        # result unchanged.
        external: list[VulnerabilityMatch] = partial.external_matches if partial is not None else []
        scan_targets = [str(pf.file_path) for pf in parsed_files]
        # Base-image coverage rows. When a caller-held partial state exists we
        # hand its list to the engine directly: rows are appended before the
        # image scans start, so they survive a cancellation by the overall
        # deadline and reach ``result_from_partial``.
        image_coverage: list[dict[str, Any]] = partial.base_images if partial is not None else []
        augmentation_degraded = False
        for name, engine in (
            (ScanEngine.BANDIT, self._bandit),
            (ScanEngine.SEMGREP, self._semgrep),
            (ScanEngine.DETECT_SECRETS, self._secrets),
            (ScanEngine.TRIVY_IAC, self._iac),
            # Base-image OS packages (`trivy image` against the baked DB). Runs
            # last: it is the only engine that pulls a container image, so it
            # must never delay the source SAST engines.
            (ScanEngine.TRIVY_IMAGE, self._image),
        ):
            if not engine.is_available():
                # The engine is part of the shipped image (Dockerfile). Absent,
                # its findings are missing: the scan is incomplete, never clean.
                augmentation_degraded = True
                reason = f"engine {name} is not installed / not on PATH"
                degraded_reasons.append(reason)
                engine_status[name] = _engine_status(ENGINE_FAILED, f"tool missing: {reason}")
                if partial is not None:
                    partial.augmentation_degraded = True
                continue
            try:
                if name == ScanEngine.TRIVY_IMAGE:
                    # Only the base-image engine pulls images; it alone takes
                    # the caller's remaining wall-clock deadline so it can
                    # budget itself instead of overrunning the whole scan.
                    found = await cast("TrivyImageScanner", engine).scan(
                        scan_targets, deadline=deadline, coverage_out=image_coverage
                    )
                else:
                    found = await engine.scan(scan_targets)
                external.extend(self._stamp_engine(found, name))
                engine_status[name] = _engine_status(ENGINE_OK)
            except ScannerExecutionError as e:
                # The tool was present and ran but errored (e.g. non-zero exit
                # with unparseable output). Its findings are missing, so the
                # augmented scan is incomplete — flag degraded rather than
                # silently dropping a SAST engine.
                augmentation_degraded = True
                partial_run = isinstance(e, ScannerPartialRunError)
                reason = (
                    f"engine {name} partial run: {e}"
                    if partial_run
                    else f"engine {name} failed to run: {e}"
                )
                degraded_reasons.append(reason)
                if partial is not None:
                    partial.augmentation_degraded = True
                # Keep whatever the engine DID collect before it failed. A
                # per-target engine (trivy-iac scans one file per invocation) can
                # have real findings in hand when a later target blows up;
                # dropping them would trade one silent lie for another —
                # "degraded, and nothing found" when something WAS found.
                if e.partial_findings:
                    external.extend(self._stamp_engine(e.partial_findings, name))
                    logger.info(
                        "kept %d partial finding(s) from failed engine %s",
                        len(e.partial_findings),
                        name,
                    )
                # A tool-reported partial run (its own errors[]) = degraded, found
                # or not. A failure with partial findings in hand (trivy-iac:
                # some targets scanned) = degraded; nothing usable = failed.
                engine_status[name] = _engine_status(
                    ENGINE_DEGRADED if (partial_run or e.partial_findings) else ENGINE_FAILED,
                    reason,
                )
                logger.error("SAST engine %s failed to run cleanly: %s", name, e)
            except Exception as e:
                # Anything else escaping an engine wrapper is an engine failure,
                # not a reason to 500 the whole scan and lose the other engines.
                augmentation_degraded = True
                reason = f"engine {name} crashed: {type(e).__name__}: {e}"
                degraded_reasons.append(reason)
                engine_status[name] = _engine_status(ENGINE_FAILED, reason)
                if partial is not None:
                    partial.augmentation_degraded = True
                logger.exception("SAST engine %s crashed", name)

        vulnerabilities = self._merge_matches(regex_vulns, external, include_low_confidence)
        vulnerabilities, suppressed = self._filter_false_positives(vulnerabilities, parsed_files)
        result = await self._analyze_security_results(vulnerabilities, parsed_files, start_time)
        result.suppressed_findings = suppressed
        result.base_images = [dict(row) for row in image_coverage]
        analysis_time = (datetime.now(UTC) - start_time).total_seconds()
        result.analysis_time_seconds = analysis_time
        result.files_failed_to_parse = files_failed_to_parse
        result.scan_degraded = (
            files_failed_to_parse > 0 or augmentation_degraded or detector_degraded
        )
        if files_failed_to_parse:
            degraded_reasons.append(f"{files_failed_to_parse} file(s) could not be parsed")
        result.degraded_reasons = list(degraded_reasons)
        result.engine_status = {str(e): dict(engine_status[e]) for e in SCAN_ENGINES}
        logger.info(
            f"Security analysis completed: {result.total_vulnerabilities_found} vulnerabilities found in {analysis_time:.2f}s"
        )
        return result

    async def scan_inline(
        self, code: str, language: str, degraded_reasons: list[str] | None = None
    ) -> list[VulnerabilityMatch]:
        """Run ONLY the in-process pattern matcher over an inline snippet.

        The same ``self.patterns`` /scan applies, with no file I/O and no
        external engine (bandit/semgrep/detect-secrets/trivy): those are
        subprocesses whose cost scales badly with adversarial input
        (detect-secrets took >300 s on a 200k-char snippet), so they belong to
        /scan, not to the inline /validate gate.

        Checks that did not finish (long-span fallback timed out or ran out of
        budget) are appended to ``degraded_reasons``.
        """
        parsed = ParseResult(
            success=True,
            file_path="<inline>",
            language=language,
            parser_used=ParserType.REGEX_FALLBACK,
        )
        lines = code.split("\n")
        matches: list[VulnerabilityMatch] = []
        budget = _FallbackBudget.for_file("<inline>")
        for pattern in self.patterns:
            if pattern.language in (language, "any"):
                matches.extend(
                    await self._apply_security_pattern(pattern, parsed, code, lines, budget)
                )
        if degraded_reasons is not None:
            degraded_reasons.extend(budget.reasons)
        return matches

    async def result_from_partial(self, partial: PartialAnalysisState) -> SecurityAnalysisResult:
        """Assemble a degraded analysis result from partially-accumulated findings.

        Used when an overall scan deadline cancels
        ``analyze_security_vulnerabilities`` mid-flight: the engines that already
        completed still hold real findings in ``partial``, so build a result from
        them (merged + de-duplicated the same way the full path does) rather than
        discarding everything. Always marked ``scan_degraded`` — a timed-out scan
        did not examine everything it was asked to, so its grade must reflect the
        incomplete coverage even though the findings it did surface are real.
        """
        vulnerabilities = self._merge_matches(
            partial.regex_matches,
            partial.external_matches,
            partial.include_low_confidence,
        )
        vulnerabilities, suppressed = self._filter_false_positives(
            vulnerabilities, partial.parsed_files
        )
        result = await self._analyze_security_results(
            vulnerabilities, partial.parsed_files, datetime.now(UTC)
        )
        result.suppressed_findings = suppressed
        result.base_images = [dict(row) for row in partial.base_images]
        result.files_failed_to_parse = partial.files_failed_to_parse
        result.scan_degraded = True
        result.degraded_reasons = [*partial.degraded_reasons, "scan deadline expired"]
        result.engine_status = {
            str(e): dict(
                partial.engine_status.get(e)
                or _engine_status(ENGINE_FAILED, "did not complete before the scan deadline")
            )
            for e in SCAN_ENGINES
        }
        return result

    @staticmethod
    def _filter_false_positives(
        vulnerabilities: list[VulnerabilityMatch], parsed_files: list[ParseResult]
    ) -> tuple[list[VulnerabilityMatch], dict[str, int]]:
        """Apply ``services.finding_filters`` over the merged findings, using
        the file contents the parse step already read. Returns the kept
        findings and the per-reason suppression counts."""
        # Imported here: finding_filters imports this module's types.
        from services.finding_filters import apply_finding_filters, scan_root, source_key

        sources: dict[str, str] = {}
        for pf in parsed_files:
            code = (pf.properties or {}).get("source_code")
            if isinstance(code, str):
                sources[source_key(str(pf.file_path))] = code
        root = scan_root([str(pf.file_path) for pf in parsed_files])
        return apply_finding_filters(vulnerabilities, sources, root)

    @staticmethod
    def _stamp_engine(
        matches: list[VulnerabilityMatch], engine: ScanEngine
    ) -> list[VulnerabilityMatch]:
        """Guarantee every finding names its engine. Producers set it themselves;
        this only fills a producer that forgot, so ``engine`` is never empty."""
        for m in matches:
            if not m.engine:
                m.engine = str(engine)
        return matches

    def _merge_matches(
        self,
        regex_matches: list[VulnerabilityMatch],
        external_matches: list[VulnerabilityMatch],
        include_low_confidence: bool,
    ) -> list[VulnerabilityMatch]:
        """Merge regex + external-engine matches, de-duplicating per
        (file, line, type) — with IaC findings scoped further by rule id.

        Within a dedup group the kept match is chosen by (a) highest severity,
        then (b) presence of a code snippet, then (c) first-seen order (regex
        before external). This keeps counts honest (no double-counting the same
        finding from two engines) while letting the real engines contribute
        findings the regex misses, and preserves the existing regex behaviour
        for findings both engines agree on.

        Two engines emit several DISTINCT findings at one file+line+type and
        must not be collapsed:
          * `trivy-image` — one finding per CVE, and every CVE of a base image
            sits on the same `FROM` line, so collapsing would keep one of
            hundreds;
          * `trivy-iac` — distinct compose checks can share a line
            (`privileged: true` + `network_mode: host` on a flow-style service),
            and two flow-style services can share both line and rule.
        For those two the key carries `pattern_id` (the rule) and `id` (which
        also carries the service for compose). Every other engine keeps the
        historical one-finding-per-key behaviour — two semgrep rules matching
        one line still report once.
        """
        if not include_low_confidence:
            external_matches = [
                m
                for m in external_matches
                if m.confidence
                not in (VulnerabilityConfidence.LOW, VulnerabilityConfidence.VERY_LOW)
            ]

        severity_rank = {
            VulnerabilitySeverity.CRITICAL: 4,
            VulnerabilitySeverity.HIGH: 3,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 1,
            VulnerabilitySeverity.INFO: 0,
        }

        def priority(m: VulnerabilityMatch) -> tuple[int, int]:
            return (severity_rank.get(m.severity, 0), 1 if m.code_snippet else 0)

        def _dedupe_key(m: VulnerabilityMatch) -> tuple[object, ...]:
            key: tuple[object, ...] = (m.file_path, m.line_start, m.vulnerability_type)
            if m.engine in (ScanEngine.TRIVY_IMAGE, ScanEngine.TRIVY_IAC):
                key += (m.pattern_id, m.id)
            return key

        merged: dict[tuple[object, ...], VulnerabilityMatch] = {}
        for m in list(regex_matches) + list(external_matches):
            key = _dedupe_key(m)
            current = merged.get(key)
            if current is None or priority(m) > priority(current):
                merged[key] = m
        return list(merged.values())

    async def _parse_file_for_security(self, file_path: Path) -> ParseResult | None:
        """Parse a file for comprehensive security analysis with language-specific processing."""
        try:
            code = self.file_service.read_file(str(file_path))
            language = self._detect_language_from_path(file_path)

            entities: list[CoreCodeEntity] = []
            relationships: list[EntityRelation] = []
            security_metadata: dict[str, Any] = {}
            parser_used = ParserType.REGEX_FALLBACK
            try:
                if language == "python":
                    (
                        entities,
                        relationships,
                        security_metadata,
                        parser_used,
                    ) = await self._parse_python_for_security(code, file_path)
                elif language in ["javascript", "typescript"]:
                    (
                        entities,
                        relationships,
                        security_metadata,
                        parser_used,
                    ) = await self._parse_js_for_security(code, file_path)
                elif language == "java":
                    (
                        entities,
                        relationships,
                        security_metadata,
                        parser_used,
                    ) = await self._parse_java_for_security(code, file_path)
                else:
                    security_metadata = await self._analyze_code_patterns(code, language)
            except (SyntaxError, ImportError, AttributeError, TypeError) as parse_error:
                logger.debug(
                    f"Language-specific parsing failed for {file_path}, using fallback: {parse_error}"
                )
                security_metadata = await self._analyze_code_patterns(code, language)
            result = ParseResult(
                success=True,
                file_path=str(file_path),
                language=language,
                parser_used=parser_used,
                ast=None,
                entities=entities,
                relationships=relationships,
                properties={
                    "source_code": code,
                    "security_metadata": security_metadata,
                    "lines_of_code": len(code.split("\n")),
                    "file_size": len(code.encode("utf-8")),
                },
            )
            return result
        except (
            FileNotFoundError,
            PermissionError,
            UnicodeDecodeError,
            MemoryError,
        ) as e:
            logger.warning(f"Failed to parse {file_path} for security analysis: {e}")
            return None

    def _detect_language_from_path(self, file_path: Path) -> str:
        """Detect programming language from file extension."""
        extension = file_path.suffix.lower()
        language_map = {
            ".py": "python",
            ".java": "java",
            ".js": "javascript",
            ".ts": "typescript",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "cpp",
            ".h": "cpp",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".cs": "csharp",
            ".php": "php",
            ".rb": "ruby",
        }
        return language_map.get(extension, "unknown")

    async def _detect_vulnerabilities(
        self,
        parsed_files: list[ParseResult],
        include_low_confidence: bool,
        degraded_reasons: list[str] | None = None,
    ) -> list[VulnerabilityMatch]:
        """Detect vulnerabilities in parsed files.

        Every check that did not finish (see ``_UNBOUNDED_ORIGINALS``) is
        appended to ``degraded_reasons``.
        """
        vulnerabilities: list[VulnerabilityMatch] = []
        for parsed_file in parsed_files:
            file_vulns = await self._scan_file_for_vulnerabilities(
                parsed_file, include_low_confidence, degraded_reasons
            )
            vulnerabilities.extend(file_vulns)
        return vulnerabilities

    async def _scan_file_for_vulnerabilities(
        self,
        parsed_file: ParseResult,
        include_low_confidence: bool,
        degraded_reasons: list[str] | None = None,
    ) -> list[VulnerabilityMatch]:
        """Scan a single file for vulnerabilities."""
        vulnerabilities: list[VulnerabilityMatch] = []
        file_path = parsed_file.file_path
        language = parsed_file.language
        try:
            content = self.file_service.read_file(str(file_path))
            lines = content.split("\n")
        except (FileNotFoundError, PermissionError, UnicodeDecodeError) as e:
            logger.warning(f"Could not read file content for {file_path}: {e}")
            # Not examined = a partial pattern run, never a clean one.
            if degraded_reasons is not None:
                degraded_reasons.append(f"{file_path}: could not be read for pattern checks: {e}")
            return vulnerabilities
        applicable_patterns = [p for p in self.patterns if p.language in (language, "any")]
        budget = _FallbackBudget.for_file(str(file_path))
        for pattern in applicable_patterns:
            matches = await self._apply_security_pattern(
                pattern, parsed_file, content, lines, budget
            )
            if not include_low_confidence:
                matches = [
                    m
                    for m in matches
                    if m.confidence
                    not in [
                        VulnerabilityConfidence.LOW,
                        VulnerabilityConfidence.VERY_LOW,
                    ]
                ]
            vulnerabilities.extend(matches)
        if degraded_reasons is not None:
            degraded_reasons.extend(budget.reasons)
        elif budget.reasons:
            logger.warning("security pattern checks incomplete: %s", budget.reasons)
        return vulnerabilities

    async def _apply_security_pattern(
        self,
        pattern: VulnerabilityPattern,
        parsed_file: ParseResult,
        content: str,
        lines: list[str],
        budget: _FallbackBudget | None = None,
    ) -> list[VulnerabilityMatch]:
        """Apply a security pattern to detect vulnerabilities.

        ``budget`` is the per-file budget of the main-equivalent fallback (see
        ``_UNBOUNDED_ORIGINALS``); its ``reasons`` collect every check that did
        not finish. Without one, a fresh per-call budget is used.
        """
        if budget is None:
            budget = _FallbackBudget.for_file(str(parsed_file.file_path))
        matches: list[VulnerabilityMatch] = []
        newline_offsets = _newline_offsets(content)
        for code_pattern in pattern.code_patterns:
            regex_matches = re.finditer(code_pattern, content, re.IGNORECASE | re.MULTILINE)
            seen_lines: set[int] = set()
            n_found = 0
            for match in regex_matches:
                if n_found >= _MAX_MATCHES_PER_PATTERN:
                    # Findings already exist for this pattern; reporting every
                    # repeat of it adds nothing but per-match work an
                    # adversarial input (`eval(` x 40,000) turns into seconds.
                    logger.warning(
                        "pattern %s: stopped after %d matches in %s",
                        pattern.id,
                        _MAX_MATCHES_PER_PATTERN,
                        parsed_file.file_path,
                    )
                    break
                vuln = self._build_match(
                    pattern, parsed_file, lines, newline_offsets, match, code_pattern
                )
                seen_lines.add(vuln.line_start)
                matches.append(vuln)
                n_found += 1
            original = _UNBOUNDED_ORIGINALS.get(code_pattern)
            if (
                original is None
                or len(content) <= _BOUNDED_SPAN_CHARS
                or n_found >= _MAX_MATCHES_PER_PATTERN
            ):
                # Within the bound the rewrite matches exactly what main did.
                continue
            for match in self._run_original(original, content, lines, pattern.id, budget):
                if n_found >= _MAX_MATCHES_PER_PATTERN:
                    break
                vuln = self._build_match(
                    pattern, parsed_file, lines, newline_offsets, match, original
                )
                if vuln.line_start in seen_lines:
                    continue
                seen_lines.add(vuln.line_start)
                matches.append(vuln)
                n_found += 1
        return matches

    @staticmethod
    def _run_original(
        original: str, content: str, lines: list[str], pattern_id: str, budget: _FallbackBudget
    ) -> list[Any]:
        """Run main's unbounded pattern under a timeout; record any non-finish."""
        remaining = budget.deadline - time.monotonic()
        if remaining <= 0:
            if not budget.exhausted:
                budget.exhausted = True
                line_no, length = _longest_line(lines)
                budget.reasons.append(
                    f"{budget.file_path}:{line_no}: rule {pattern_id}: per-file budget "
                    f"({_FALLBACK_FILE_BUDGET_S:g}s) for long-span checks exhausted "
                    f"(longest line {length} chars); this and later rules' spans beyond "
                    f"{_BOUNDED_SPAN_CHARS} chars were not checked"
                )
            return []
        timeout = min(_FALLBACK_CALL_TIMEOUT_S, remaining)
        found: list[Any] = []
        try:
            for match in regex.finditer(
                original, content, flags=regex.IGNORECASE | regex.MULTILINE, timeout=timeout
            ):
                found.append(match)
                if len(found) >= _MAX_MATCHES_PER_PATTERN:
                    break
        except TimeoutError:
            line_no, length = _longest_line(lines)
            budget.reasons.append(
                f"{budget.file_path}:{line_no}: rule {pattern_id}: long-span check timed out "
                f"after {timeout:.2f}s (longest line {length} chars); sources and sinks more "
                f"than {_BOUNDED_SPAN_CHARS} chars apart were not fully checked"
            )
        return found

    def _build_match(
        self,
        pattern: VulnerabilityPattern,
        parsed_file: ParseResult,
        lines: list[str],
        newline_offsets: list[int],
        match: Any,
        code_pattern: str,
    ) -> VulnerabilityMatch:
        """One finding for ``match`` (a ``re`` or ``regex`` match object)."""
        text = match.group()
        line_start = bisect.bisect_left(newline_offsets, match.start()) + 1
        line_end = bisect.bisect_left(newline_offsets, match.end()) + 1
        context = self._extract_vulnerability_context(lines, line_start, line_end, parsed_file)
        confidence = self._calculate_vulnerability_confidence(pattern, text, context)
        # Add CVE references to the match
        cve_references = (
            pattern.references
            if pattern.references
            else self.get_cve_references(pattern.vulnerability_type)
        )

        vuln_match = VulnerabilityMatch(
            id=f"{pattern.id}_{parsed_file.file_path}_{line_start}",
            vulnerability_type=pattern.vulnerability_type,
            severity=pattern.severity,
            confidence=confidence,
            file_path=parsed_file.file_path,
            language=parsed_file.language,
            line_start=line_start,
            line_end=line_end,
            pattern_id=pattern.id,
            title=pattern.name,
            description=pattern.description,
            code_snippet=text,
            cwe_ids=pattern.cwe_ids,
            owasp_categories=pattern.owasp_categories,
            cvss_score=self.severity_scores[pattern.severity],
            matched_patterns=[code_pattern],
            context_evidence=context,
            function_name=context.get("function_name"),
            class_name=context.get("class_name"),
            references=cve_references,
            engine=ScanEngine.PATTERN,
        )
        vuln_match.remediation_advice = self._get_remediation_advice(pattern)
        vuln_match.resolve_suggestions = self._get_fix_suggestions(pattern)

        # Log CVE matches
        if cve_references:
            logger.info(
                f"Security vulnerability detected: {pattern.name} ({pattern.vulnerability_type}) "
                f"in {parsed_file.file_path}:{line_start} - "
                f"Related CVEs: {', '.join(cve_references)}"
            )
        else:
            logger.info(
                f"Security vulnerability detected: {pattern.name} ({pattern.vulnerability_type}) "
                f"in {parsed_file.file_path}:{line_start}"
            )

        return vuln_match

    def _extract_vulnerability_context(
        self, lines: list[str], line_start: int, line_end: int, parsed_file: ParseResult
    ) -> dict[str, Any]:
        """Extract context information around a vulnerability."""
        context: dict[str, Any] = {}
        for entity in parsed_file.entities:
            if entity.line_number <= line_start <= (
                entity.end_line_number or entity.line_number
            ) or entity.line_number <= line_end <= (entity.end_line_number or entity.line_number):
                if entity.type == EntityType.FUNCTION:
                    context["function_name"] = entity.name
                elif entity.type == EntityType.CLASS:
                    context["class_name"] = entity.name
        context_start = max(0, line_start - 6)
        context_end = min(len(lines), line_end + 5)
        context["surrounding_code"] = lines[context_start:context_end]
        # Keyword sniffing looks at a bounded prefix of each line: on a single
        # 200,000-char line, searching the whole line once per match (up to
        # _MAX_MATCHES_PER_PATTERN) cost ~1.4 s per pattern.
        heads = [line[:_CONTEXT_LINE_CHARS] for line in context["surrounding_code"]]
        context["has_input_validation"] = any(
            re.search("validate|sanitize|escape|filter", line, re.IGNORECASE) for line in heads
        )
        context["has_error_handling"] = any(
            re.search("try|catch|except|error", line, re.IGNORECASE) for line in heads
        )
        return context

    # Vulnerability types that are inherently critical regardless of pattern severity.
    # These represent dangerous operations where a match strongly indicates a real issue.
    CRITICAL_VULNERABILITY_TYPES: frozenset[VulnerabilityType] = frozenset(
        {
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.DESERIALIZATION,
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.LOG4J_RCE,
            VulnerabilityType.SPRING_RCE,
        }
    )

    def _calculate_vulnerability_confidence(
        self, pattern: VulnerabilityPattern, matched_code: str, context: dict[str, Any]
    ) -> VulnerabilityConfidence:
        """Calculate confidence level for a vulnerability detection."""
        # Base confidence depends on pattern severity:
        # CRITICAL patterns (os.system, subprocess, eval, exec, pickle, etc.) are
        # inherently dangerous — their presence IS the vulnerability.
        # HIGH patterns (dangerous imports, unsafe deserialization) are likely issues.
        # MEDIUM/LOW/INFO patterns need contextual keywords to raise confidence.
        if pattern.severity == VulnerabilitySeverity.CRITICAL:
            confidence_score = 0.9
        elif pattern.severity == VulnerabilitySeverity.HIGH:
            confidence_score = 0.7
        else:
            confidence_score = 0.5

        # Critical vulnerability types get a confidence floor of 0.85 regardless
        # of severity. Command injection, SQL injection, deserialization, and RCE
        # patterns are dangerous enough that they should always be reported.
        if pattern.vulnerability_type in self.CRITICAL_VULNERABILITY_TYPES:
            confidence_score = max(confidence_score, 0.85)
        if any(keyword in matched_code.lower() for keyword in ["password", "secret", "key"]):
            confidence_score += 0.3
        if "user" in matched_code.lower() or "input" in matched_code.lower():
            confidence_score += 0.2
        if context.get("has_input_validation", False):
            confidence_score -= 0.2
        if context.get("has_error_handling", False):
            confidence_score -= 0.1
        if confidence_score >= 0.95:
            return VulnerabilityConfidence.VERY_HIGH
        elif confidence_score >= 0.85:
            return VulnerabilityConfidence.HIGH
        elif confidence_score >= 0.7:
            return VulnerabilityConfidence.MEDIUM
        elif confidence_score >= 0.5:
            return VulnerabilityConfidence.LOW
        else:
            return VulnerabilityConfidence.VERY_LOW

    def _get_remediation_advice(self, pattern: VulnerabilityPattern) -> str:
        """Get remediation advice for a vulnerability pattern."""
        advice_map = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements instead of string concatenation.",
            VulnerabilityType.XSS: "Sanitize and escape user input before rendering. Use content security policies.",
            VulnerabilityType.COMMAND_INJECTION: "Use subprocess with shell=False and validate input parameters.",
            VulnerabilityType.HARDCODED_CREDENTIALS: "Move credentials to environment variables or secure configuration.",
            VulnerabilityType.WEAK_CRYPTOGRAPHY: "Use strong cryptographic algorithms like SHA-256 or AES-256.",
            VulnerabilityType.BUFFER_OVERFLOW: "Use safer string functions like strncpy, strncat, or snprintf.",
            VulnerabilityType.PATH_TRAVERSAL: "Validate and canonicalize file paths. Reject paths containing '..' or absolute paths.",
            VulnerabilityType.DESERIALIZATION: "Avoid deserializing untrusted data. Use allow-lists for permitted classes.",
            VulnerabilityType.LOG4J_RCE: "Upgrade Log4j to 2.17.1 or later. Disable JNDI lookups via log4j2.formatMsgNoLookups=true.",
            VulnerabilityType.SPRING_RCE: "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Restrict data binding with @InitBinder.",
            VulnerabilityType.LDAP_INJECTION: "Use parameterized LDAP queries and validate/escape special characters in user input.",
            VulnerabilityType.XML_INJECTION: "Disable external entity resolution in XML parsers. Set FEATURE_SECURE_PROCESSING.",
            VulnerabilityType.INSECURE_RANDOM: "Use cryptographically secure random number generators (secrets module, SecureRandom).",
            VulnerabilityType.RACE_CONDITION: "Use proper synchronization primitives (locks, mutexes) to protect shared resources.",
            VulnerabilityType.CSRF: "Implement CSRF tokens for state-changing requests. Use SameSite cookie attribute.",
        }
        return advice_map.get(
            pattern.vulnerability_type, "Review code for security best practices."
        )

    def _get_fix_suggestions(self, pattern: VulnerabilityPattern) -> list[str]:
        """Get specific correction suggestions for a vulnerability pattern."""
        suggestions_map = {
            VulnerabilityType.SQL_INJECTION: [
                "Replace string concatenation with parameterized queries",
                "Use ORM query builders when possible",
                "Validate and sanitize all user inputs",
                "Implement proper input escaping",
            ],
            VulnerabilityType.XSS: [
                "Use template engines with auto-escaping",
                "Implement Content Security Policy (CSP)",
                "Validate and sanitize user input",
                "Use textContent instead of innerHTML",
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "Use subprocess with explicit arguments list",
                "Validate and whitelist allowed commands",
                "Avoid shell=True parameter",
                "Implement proper input sanitization",
            ],
            VulnerabilityType.HARDCODED_CREDENTIALS: [
                "Store secrets in environment variables or a vault",
                "Use a secrets management service (HashiCorp Vault, AWS Secrets Manager)",
                "Add credential patterns to .gitignore and pre-commit hooks",
            ],
            VulnerabilityType.WEAK_CRYPTOGRAPHY: [
                "Replace MD5/SHA1 with SHA-256 or SHA-3",
                "Replace DES/RC4 with AES-256-GCM",
                "Use bcrypt/argon2 for password hashing",
            ],
            VulnerabilityType.BUFFER_OVERFLOW: [
                "Replace strcpy with strncpy or strlcpy",
                "Replace sprintf with snprintf",
                "Use bounds-checked container classes",
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                "Canonicalize paths with realpath() before access",
                "Validate paths against an allowed base directory",
                "Reject paths containing '..' sequences",
            ],
            VulnerabilityType.DESERIALIZATION: [
                "Use safe serialization formats (JSON) instead of native serialization",
                "Implement class allow-lists for deserialization",
                "Validate integrity of serialized data before deserializing",
            ],
            VulnerabilityType.LOG4J_RCE: [
                "Upgrade to Log4j 2.17.1 or later",
                "Set log4j2.formatMsgNoLookups=true",
                "Remove JndiLookup class from classpath",
            ],
            VulnerabilityType.SPRING_RCE: [
                "Upgrade Spring Framework to 5.3.18+ or 5.2.20+",
                "Use @InitBinder to restrict allowed fields",
                "Avoid using ClassLoader-based property access",
            ],
        }
        return suggestions_map.get(pattern.vulnerability_type, ["Review security best practices"])

    def get_cve_references(self, vulnerability_type: VulnerabilityType) -> list[str]:
        """Get relevant CVE IDs for a vulnerability type.

        Args:
            vulnerability_type: The type of vulnerability

        Returns:
            List of relevant CVE IDs
        """
        cve_map = {
            VulnerabilityType.SQL_INJECTION: [
                "CVE-2019-9193",
                "CVE-2020-1938",
                "CVE-2021-22945",
            ],
            VulnerabilityType.XSS: [
                "CVE-2020-5410",
                "CVE-2021-3129",
                "CVE-2022-0536",
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "CVE-2019-1010317",
                "CVE-2015-4852",
                "CVE-2016-3720",
            ],
            VulnerabilityType.HARDCODED_CREDENTIALS: [
                "CVE-2021-3807",
                "CVE-2021-43565",
            ],
            VulnerabilityType.WEAK_CRYPTOGRAPHY: [
                "CVE-2013-5915",
                "CVE-2012-2459",
            ],
            VulnerabilityType.BUFFER_OVERFLOW: [
                "CVE-2014-1732",
                "CVE-2013-4152",
            ],
            VulnerabilityType.LOG4J_RCE: [
                "CVE-2021-44228",
                "CVE-2021-45046",
                "CVE-2021-45105",
                "CVE-2021-44832",
            ],
            VulnerabilityType.SPRING_RCE: [
                "CVE-2022-22965",
                "CVE-2022-22947",
            ],
            VulnerabilityType.DESERIALIZATION: [
                "CVE-2015-4852",
                "CVE-2015-6420",
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                "CVE-2021-22911",
                "CVE-2022-24999",
            ],
            VulnerabilityType.LDAP_INJECTION: [
                "CVE-2021-27906",
            ],
            VulnerabilityType.XML_INJECTION: [
                "CVE-2013-2156",
                "CVE-2020-8949",
            ],
            VulnerabilityType.INSECURE_RANDOM: [
                "CVE-2008-0166",
            ],
            VulnerabilityType.RACE_CONDITION: [
                "CVE-2016-2183",
            ],
            VulnerabilityType.CSRF: [
                "CVE-2012-0394",
            ],
        }
        cves = cve_map.get(vulnerability_type, [])
        logger.debug(
            f"Retrieved {len(cves)} CVE references for vulnerability type: {vulnerability_type}"
        )
        return cves

    async def _analyze_security_results(
        self,
        vulnerabilities: list[VulnerabilityMatch],
        parsed_files: list[ParseResult],
        start_time: datetime,
    ) -> SecurityAnalysisResult:
        """Analyze and categorize security results."""
        result = SecurityAnalysisResult(
            total_files_analyzed=len(parsed_files),
            total_vulnerabilities_found=len(vulnerabilities),
            analysis_time_seconds=0.0,
        )
        for vuln in vulnerabilities:
            if vuln.vulnerability_type not in result.vulnerabilities_by_type:
                result.vulnerabilities_by_type[vuln.vulnerability_type] = []
            result.vulnerabilities_by_type[vuln.vulnerability_type].append(vuln)
            if vuln.severity not in result.vulnerabilities_by_severity:
                result.vulnerabilities_by_severity[vuln.severity] = []
            result.vulnerabilities_by_severity[vuln.severity].append(vuln)
            if vuln.confidence not in result.vulnerabilities_by_confidence:
                result.vulnerabilities_by_confidence[vuln.confidence] = []
            result.vulnerabilities_by_confidence[vuln.confidence].append(vuln)
            if vuln.language not in result.vulnerabilities_by_language:
                result.vulnerabilities_by_language[vuln.language] = []
            result.vulnerabilities_by_language[vuln.language].append(vuln)
        result.critical_issues_count = len(
            result.vulnerabilities_by_severity.get(VulnerabilitySeverity.CRITICAL, [])
        )
        result.high_severity_count = len(
            result.vulnerabilities_by_severity.get(VulnerabilitySeverity.HIGH, [])
        )
        risk_score = 0.0
        for vuln in vulnerabilities:
            severity_weight = {
                VulnerabilitySeverity.CRITICAL: 10.0,
                VulnerabilitySeverity.HIGH: 7.0,
                VulnerabilitySeverity.MEDIUM: 4.0,
                VulnerabilitySeverity.LOW: 1.0,
                VulnerabilitySeverity.INFO: 0.1,
            }
            confidence_weight = {
                VulnerabilityConfidence.VERY_HIGH: 1.0,
                VulnerabilityConfidence.HIGH: 0.8,
                VulnerabilityConfidence.MEDIUM: 0.6,
                VulnerabilityConfidence.LOW: 0.4,
                VulnerabilityConfidence.VERY_LOW: 0.2,
            }
            risk_score += severity_weight[vuln.severity] * confidence_weight[vuln.confidence]
        result.overall_risk_score = min(risk_score / max(len(parsed_files), 1), 100.0)
        if vulnerabilities:
            vuln_counts = Counter(v.vulnerability_type for v in vulnerabilities)
            result.most_common_vulnerability = vuln_counts.most_common(1)[0][0]
        file_vuln_counts = Counter(v.file_path for v in vulnerabilities)
        result.security_hotspots = [
            file_path for file_path, count in file_vuln_counts.items() if count >= 3
        ]
        result.priority_fixes = [
            v
            for v in vulnerabilities
            if v.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]
            and v.confidence in [VulnerabilityConfidence.VERY_HIGH, VulnerabilityConfidence.HIGH]
        ]
        for parsed_file in parsed_files:
            lang = parsed_file.language
            result.language_distribution[lang] = result.language_distribution.get(lang, 0) + 1
        return result

    async def _parse_python_for_security(
        self, code: str, file_path: Path
    ) -> tuple[list[Any], list[Any], dict[str, Any], Any]:
        """Parse Python code for security-specific analysis."""
        import ast

        entities: list[CoreCodeEntity] = []
        relationships: list[EntityRelation] = []
        security_metadata: dict[str, Any] = {
            "imports": [],
            "function_calls": [],
            "string_literals": [],
            "security_patterns": {},
            "dangerous_functions": [],
        }
        try:
            tree = ast.parse(code)

            class SecurityASTVisitor(ast.NodeVisitor):
                """AST Visitor for analyzing security-related constructs in the code."""

                def visit_Import(self, node) -> None:
                    """Visit and process import statements in the AST."""
                    for alias in node.names:
                        security_metadata["imports"].append(
                            {"name": alias.name, "line": node.lineno, "type": "import"}
                        )
                    self.generic_visit(node)

                def visit_ImportFrom(self, node) -> None:
                    """Visit and process from-import statements in the AST."""
                    module = node.module or ""
                    for alias in node.names:
                        security_metadata["imports"].append(
                            {
                                "name": f"{module}.{alias.name}",
                                "line": node.lineno,
                                "type": "from_import",
                            }
                        )
                    self.generic_visit(node)

                def visit_Call(self, node) -> None:
                    """Visit and track function calls for security analysis."""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        security_metadata["function_calls"].append(
                            {"name": func_name, "line": node.lineno}
                        )
                        if func_name in ["eval", "exec", "compile", "__import__"]:
                            security_metadata["dangerous_functions"].append(
                                {
                                    "function": func_name,
                                    "line": node.lineno,
                                    "risk": "high",
                                }
                            )
                    elif isinstance(node.func, ast.Attribute):
                        attr_name = node.func.attr
                        security_metadata["function_calls"].append(
                            {
                                "name": attr_name,
                                "line": node.lineno,
                                "args": len(node.args),
                                "type": "method_call",
                            }
                        )
                    self.generic_visit(node)

                def visit_Constant(self, node) -> None:
                    """Visit and track string literals for security pattern analysis."""
                    # Handle string constants (replaces deprecated visit_Str)
                    if isinstance(node.value, str) and len(node.value) > 5:
                        security_metadata["string_literals"].append(
                            {
                                "value": node.value[:100],
                                "line": node.lineno,
                                "length": len(node.value),
                            }
                        )
                    self.generic_visit(node)

                def visit_FunctionDef(self, node) -> None:
                    """Visit and create entities for function definitions in the AST."""
                    entity = CoreCodeEntity(
                        id=f"func_{file_path.stem}_{node.name}_{node.lineno}",
                        name=node.name,
                        type=EntityType.FUNCTION,
                        language="python",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        end_line_number=None,
                        column_start=None,
                        column_end=None,
                        visibility=None,
                        code_snippet=None,
                        docstring=None,
                        source_code=None,
                    )
                    entities.append(entity)
                    self.generic_visit(node)

            visitor = SecurityASTVisitor()
            visitor.visit(tree)
            security_metadata["security_patterns"] = await self._analyze_python_security_patterns(
                code
            )
            return (entities, relationships, security_metadata, ParserType.TREE_SITTER)
        except (SyntaxError, UnicodeDecodeError, MemoryError) as e:
            logger.debug(f"Python AST parsing failed for {file_path}: {e}")
            security_metadata = await self._analyze_code_patterns(code, "python")
            return ([], [], security_metadata, ParserType.REGEX_FALLBACK)

    async def _parse_js_for_security(
        self, code: str, file_path: Path
    ) -> tuple[list[Any], list[Any], dict[str, Any], Any]:
        """Parse JavaScript/TypeScript code for security-specific analysis."""
        import re

        entities: list[CoreCodeEntity] = []
        relationships: list[EntityRelation] = []
        security_metadata: dict[str, Any] = {
            "imports": [],
            "function_calls": [],
            "dom_access": [],
            "security_patterns": {},
            "dangerous_patterns": [],
        }
        patterns = {
            "requires": "require\\s*\\(\\s*['\\\"]([^'\\\"]+)['\\\"]\\s*\\)",
            "imports": "import\\s(?>.{0,300}?\\sfrom\\s{1,20}['\\\"])([^'\\\"\\n]{1,300})['\\\"]",
            "eval_calls": "eval\\s*\\(",
            "innerHTML": "\\.innerHTML\\s*=",
            "document_write": "document\\.write\\s*\\(",
            "function_calls": "\\b(\\w+)\\s*\\(",
            "dom_selectors": "document\\.(getElementById|querySelector|getElementsBy\\w+)\\s*\\(",
        }
        lines = code.split("\n")
        for line_num, line in enumerate(lines, 1):
            for match in re.finditer(patterns["requires"], line):
                security_metadata["imports"].append(
                    {"name": match.group(1), "line": line_num, "type": "require"}
                )
            for match in re.finditer(patterns["imports"], line):
                security_metadata["imports"].append(
                    {"name": match.group(1), "line": line_num, "type": "import"}
                )
            if re.search(patterns["eval_calls"], line):
                security_metadata["dangerous_patterns"].append(
                    {"pattern": "eval_usage", "line": line_num, "risk": "high"}
                )
            if re.search(patterns["innerHTML"], line):
                security_metadata["dangerous_patterns"].append(
                    {
                        "pattern": "innerHTML_assignment",
                        "line": line_num,
                        "risk": "medium",
                    }
                )
            if re.search(patterns["document_write"], line):
                security_metadata["dangerous_patterns"].append(
                    {"pattern": "document_write", "line": line_num, "risk": "medium"}
                )
            for match in re.finditer(patterns["dom_selectors"], line):
                security_metadata["dom_access"].append({"method": match.group(1), "line": line_num})
        security_metadata["security_patterns"] = await self._analyze_js_security_patterns(code)
        return (entities, relationships, security_metadata, ParserType.REGEX_FALLBACK)

    async def _parse_java_for_security(
        self, code: str, file_path: Path
    ) -> tuple[list[Any], list[Any], dict[str, Any], Any]:
        """Parse Java code for security-specific analysis."""
        import re

        entities: list[CoreCodeEntity] = []
        relationships: list[EntityRelation] = []
        security_metadata: dict[str, Any] = {
            "imports": [],
            "method_calls": [],
            "sql_patterns": [],
            "security_patterns": {},
            "dangerous_methods": [],
        }
        patterns = {
            "imports": "import\\s+([\\w\\.\\*]+);",
            "sql_patterns": "(Statement|PreparedStatement|createStatement|executeQuery|executeUpdate)",
            "reflection": "(Class\\.forName|Method\\.invoke|Constructor\\.newInstance)",
            "deserialization": "(ObjectInputStream|readObject|XMLDecoder)",
            "file_operations": "(FileInputStream|FileOutputStream|File\\s*\\()",
        }
        lines = code.split("\n")
        for line_num, line in enumerate(lines, 1):
            for match in re.finditer(patterns["imports"], line):
                security_metadata["imports"].append(
                    {"name": match.group(1), "line": line_num, "type": "import"}
                )
            if re.search(patterns["sql_patterns"], line):
                security_metadata["sql_patterns"].append(
                    {"line": line_num, "content": line.strip()[:100]}
                )
            if re.search(patterns["reflection"], line):
                security_metadata["dangerous_methods"].append(
                    {"pattern": "reflection", "line": line_num, "risk": "medium"}
                )
            if re.search(patterns["deserialization"], line):
                security_metadata["dangerous_methods"].append(
                    {"pattern": "deserialization", "line": line_num, "risk": "high"}
                )
        security_metadata["security_patterns"] = await self._analyze_java_security_patterns(code)
        return (entities, relationships, security_metadata, ParserType.REGEX_FALLBACK)

    async def _analyze_python_security_patterns(self, code: str) -> dict[str, Any]:
        """Analyze Python-specific security patterns."""
        patterns = {
            "sql_injection": len(
                re.findall(
                    "[\"\\'](?>.{0,120}?\\+)(?>.{0,120}?[\"\\'])(?>.{0,120}?sql)|query",
                    code,
                    re.IGNORECASE,
                )
            ),
            "command_injection": len(re.findall("os\\.system|subprocess\\.call|eval\\(", code)),
            "hardcoded_secrets": len(
                re.findall(
                    "password\\s*=\\s*[\"\\'][^\"\\']+[\"\\']|api_key\\s*=\\s*[\"\\'][^\"\\']+[\"\\']",
                    code,
                    re.IGNORECASE,
                )
            ),
            "unsafe_deserialization": len(re.findall("pickle\\.loads|yaml\\.load(?!_safe)", code)),
            "path_traversal": len(
                re.findall("open\\s*\\(.{0,120}\\+|os\\.path\\.join\\(.{0,120}user", code)
            ),
        }
        return patterns

    async def _analyze_js_security_patterns(self, code: str) -> dict[str, Any]:
        """Analyze JavaScript-specific security patterns."""
        patterns = {
            "xss_vulnerability": len(
                re.findall("innerHTML\\s*=|document\\.write\\(.{0,120}\\+", code)
            ),
            "eval_usage": len(re.findall("eval\\s*\\(|Function\\s*\\(", code)),
            "prototype_pollution": len(re.findall("__proto__|constructor\\.prototype", code)),
            "unsafe_redirect": len(
                re.findall("location\\.href\\s*=.{0,120}\\+|window\\.open\\(.{0,120}\\+", code)
            ),
            "dom_based_xss": len(re.findall("location\\.hash|location\\.search", code)),
        }
        return patterns

    async def _analyze_java_security_patterns(self, code: str) -> dict[str, Any]:
        """Analyze Java-specific security patterns."""
        patterns = {
            "sql_injection": len(
                re.findall(
                    'Statement(?>.{0,120}?executeQuery\\()(?>.{0,120}?\\+)|"(?>.{0,120}?"\\s*\\+)(?>.{0,120}?executeQuery)',
                    code,
                )
            ),
            "command_injection": len(
                re.findall("Runtime\\.exec|ProcessBuilder.{0,120}start", code)
            ),
            "xxe_vulnerability": len(re.findall("DocumentBuilderFactory|SAXParserFactory", code)),
            "unsafe_deserialization": len(re.findall("ObjectInputStream.{0,120}readObject", code)),
            "ldap_injection": len(
                re.findall("LdapContext|DirContext(?>.{0,120}?search\\()(?>.{0,120}?\\+)", code)
            ),
        }
        return patterns

    async def _analyze_code_patterns(self, code: str, language: str) -> dict[str, Any]:
        """Fallback method for general code pattern analysis."""
        patterns = {
            "total_lines": len(code.split("\n")),
            "comment_lines": len(re.findall("^[ \\t]*[#/]", code, re.MULTILINE)),
            "string_literals": len(re.findall("[\"\\'][^\"\\']*[\"\\']", code)),
            "function_definitions": len(
                re.findall("def\\s+\\w+|function\\s+\\w+|public\\s+\\w+\\s+\\w+\\s*\\(", code)
            ),
            "security_keywords": len(
                re.findall("password|secret|key|token|auth|security", code, re.IGNORECASE)
            ),
        }
        return patterns


_security_detector: SecurityVulnerabilityDetector | None = None
_security_detector_lock = asyncio.Lock()


def get_security_detector() -> SecurityVulnerabilityDetector:
    """Get or create the global security vulnerability detector instance.

    Synchronous accessor. Building the singleton runs blocking ``subprocess.run
    --version`` probes in the bandit/secrets scanner ``__init__``s (up to ~20s
    if a tool binary is wedged), so this must NOT be the FIRST caller on a
    running event loop — prefer :func:`get_security_detector_async` in async
    handlers and eager-warm at startup. This sync path stays for the sync
    ``__init__`` callers (``SecurityScanService``, ``UnifiedSecurityScanner``)
    and tests; once the singleton is warmed it returns instantly.
    """
    global _security_detector
    if _security_detector is None:
        _security_detector = SecurityVulnerabilityDetector()
        logger.info("Initialized global security vulnerability detector")
    return _security_detector


async def get_security_detector_async() -> SecurityVulnerabilityDetector:
    """Async accessor that never blocks the event loop on first build.

    The singleton's construction runs blocking subprocess version-probes; doing
    that on the loop would stall every concurrent request for the probe
    duration. So on a cache miss we build via :func:`asyncio.to_thread`, guarded
    by a module-level lock with double-checked locking so N concurrent callers
    trigger exactly one build. Once cached, returns on the lock-free fast path.
    """
    global _security_detector
    if _security_detector is not None:
        return _security_detector
    async with _security_detector_lock:
        # Re-check under the lock: another coroutine may have built it while we
        # were suspended acquiring the lock (double-checked locking).
        if _security_detector is None:
            _security_detector = await asyncio.to_thread(SecurityVulnerabilityDetector)
            logger.info("Initialized global security vulnerability detector (off-thread)")
    return _security_detector
