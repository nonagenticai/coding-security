"""Identity headers for calls coding-security makes to its siblings.

Every outbound call in this service goes to coding-containers or coding-github
inside the mesh, and every one of them currently carries a *bare*
``X-Tenant-Id``. That works today only because those callees still trust the
header on the strength of the source pod's CIDR — a network position, not a
credential. Once they are flipped to ``TRUST_TENANT_HEADER=false`` a bare
header proves nothing and every one of these calls 401s: container scans,
dependency scans, package upgrades, PR creation.

This module is the one place that decides what an outbound call says about who
it is, so the "attach the credential" step has a single failure mode instead of
nine independently-forgettable copies of a header dict.

What goes on the wire
---------------------
* ``Authorization: Bearer <CODING_SERVICE_TOKEN>`` — **this service's own**
  licence. Never a forwarded copy of an inbound one: most of these calls are
  detached (worker-dequeued scans, background upgrades) and have no inbound
  request to borrow from.
* ``X-Tenant-Id`` — the **customer** the call is made for.

The two must stay in separate headers. Putting the credential into
``X-Tenant-Id`` would make the callee resolve the tenant from our token and
collapse every customer into ``svc-coding-security``'s own tenant — the exact
cross-tenant bug the header exists to prevent. The callee honours the asserted
tenant only when our subject is in its ``CODING_ONBEHALF_SUBJECTS`` allowlist.
"""

from __future__ import annotations

import os

from coding_client.auth.outbound import optional_tenant_headers, tenant_headers

__all__ = ["optional_sibling_headers", "service_token", "sibling_headers"]


def service_token() -> str | None:
    """This service's own licence, read per call so a rotation needs no restart.

    Read from the environment at call time, never captured at import: a module
    constant would freeze whatever the value was when the first import ran, and
    would make every test that needs a token have to reload the module.

    The ``or None`` normalises a set-but-empty variable to absent. Both SDK
    builders test the token for truthiness, so this is belt-and-braces rather
    than the thing that stops a bare ``Bearer `` going out — stated plainly so
    nobody later "simplifies" it believing it was load-bearing.
    """
    return os.getenv("CODING_SERVICE_TOKEN") or None


def sibling_headers(tenant_id: str | None, *, operation: str) -> dict[str, str]:
    """Headers for a sibling call whose target resource is scoped by the tenant.

    Raises ``TenantMissingError`` when the tenant is absent, because at these
    call sites a guessed tenant is a cross-tenant authorisation bug, not a lost
    log line.
    """
    return tenant_headers(tenant_id, operation=operation, service_token=service_token())


def optional_sibling_headers(tenant_id: str | None) -> dict[str, str]:
    """Headers for a sibling call the tenant merely *narrows*, and may be absent.

    Absent stays absent — the header is omitted rather than defaulted, so an
    unscoped lookup cannot silently address another tenant's data. The
    credential is still attached: proving who we are is not a claim about whose
    data we want.
    """
    return optional_tenant_headers(tenant_id, service_token=service_token())
