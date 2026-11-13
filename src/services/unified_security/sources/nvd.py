"""NVD CVSS enrichment for unified security findings."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from config.settings import get_settings
from services.nvd_client import NVDClient
from services.unified_security.base import SecurityFinding

if TYPE_CHECKING:
    from services.unified_security.scanner import UnifiedSecurityScanner

logger = logging.getLogger(__name__)


async def enrich(
    scanner: UnifiedSecurityScanner,
    findings: list[SecurityFinding],
    errors: list[str],
) -> None:
    """Enrich findings with NVD CVSS scores (optional, non-blocking).

    Collects unique CVE IDs, batch-fetches CVSS data, and applies scores.
    """
    cve_ids = list(set(f.cve_id for f in findings if f.cve_id and f.cve_id.startswith("CVE")))

    if not cve_ids:
        return

    try:
        settings = get_settings()
        if scanner.nvd_client is None:
            scanner.nvd_client = NVDClient(api_key=settings.nvd_api_key)

        nvd_data = await scanner.nvd_client.batch_get_cves(cve_ids)

        enriched_count = 0
        for finding in findings:
            if finding.cve_id and finding.cve_id in nvd_data:
                cvss = nvd_data[finding.cve_id]
                finding.cvss_score = cvss.cvss_v31_score
                finding.cvss_severity = cvss.cvss_v31_severity
                enriched_count += 1

        logger.info(f"NVD enrichment: {enriched_count}/{len(cve_ids)} findings enriched")

    except Exception as e:
        error_msg = f"NVD enrichment failed: {str(e)}"
        logger.warning(error_msg)
        errors.append(error_msg)

    finally:
        if scanner.nvd_client:
            try:
                await scanner.nvd_client.close()
            except Exception as e:
                logger.debug(f"Error closing NVD client: {e}")
