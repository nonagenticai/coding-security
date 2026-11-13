"""Unified security scanning package.

Public API:
- UnifiedSecurityScanner: orchestrator class
- get_unified_security_scanner: singleton accessor
- SecurityFinding / SecurityFindingSeverity / SecurityFindingSource: finding model + enums
- UnifiedSecurityReport: top-level report pydantic model
"""

from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
    UnifiedSecurityReport,
)
from services.unified_security.scanner import (
    UnifiedSecurityScanner,
    get_unified_security_scanner,
)

__all__ = [
    "SecurityFinding",
    "SecurityFindingSeverity",
    "SecurityFindingSource",
    "UnifiedSecurityReport",
    "UnifiedSecurityScanner",
    "get_unified_security_scanner",
]
