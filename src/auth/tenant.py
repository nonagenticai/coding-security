"""Tenant middleware + dependencies — re-exported from coding_client SDK.

This module is a thin re-export of ``coding_client.auth.tenant`` so the
canonical implementation lives in the SDK and all coding-* services share
identical tenant-extraction behaviour. The previous local copy was a
53-line module that unconditionally returned ``DEFAULT_TENANT_ID`` when
no ``X-Tenant-Id`` header (or ``tenant_id`` query parameter) was present.

The SDK is stricter: it only falls back to ``DEFAULT_TENANT_ID`` for
requests originating from a trusted-CIDR network (127.0.0.1/32, ::1/128,
RFC1918) and otherwise raises 401. This aligns coding-security with every
other coding-* service's auth surface.

Mirrors coding-testing PR #14 (R-7, squash 53b92d8) and coding-analysis
PR #20 (R-7a, squash fa35592).
"""

from coding_client.auth.tenant import (
    DEFAULT_TENANT_ID,
    LICENSE_INTROSPECT_URL,
    TENANT_ID_HEADER,
    TRUSTED_NETWORKS,
    TenantMiddleware,
    _introspect_license,
    _is_trusted_network,
    _license_cache,
    check_tenant_access,
    get_current_user_with_tenant,
    get_tenant_id,
    optional_tenant,
    require_same_tenant,
    require_tenant,
)

__all__ = [
    "DEFAULT_TENANT_ID",
    "LICENSE_INTROSPECT_URL",
    "TENANT_ID_HEADER",
    "TRUSTED_NETWORKS",
    "TenantMiddleware",
    "_introspect_license",
    "_is_trusted_network",
    "_license_cache",
    "check_tenant_access",
    "get_current_user_with_tenant",
    "get_tenant_id",
    "optional_tenant",
    "require_same_tenant",
    "require_tenant",
]
