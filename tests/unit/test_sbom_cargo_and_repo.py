"""SBOM: purl -> ecosystem mapping; an unsafe `repo` selector is a 422."""

from __future__ import annotations

import pytest

from services.syft_scanner import ecosystem_from_purl


@pytest.mark.parametrize(
    ("purl", "eco"),
    [
        ("pkg:cargo/smallvec@1.6.0", "crates.io"),
        ("pkg:pypi/requests@2.31.0", "pypi"),
        ("pkg:npm/left-pad@1.0.0", "npm"),
        ("pkg:deb/debian/libc6@2.36", None),
        (None, None),
        ("not-a-purl", None),
    ],
)
def test_ecosystem_from_purl(purl, eco):
    assert ecosystem_from_purl(purl) == eco


def test_sbom_unsafe_repo_is_422(test_client, tenant_headers):
    resp = test_client.post(
        "/api/security/sbom/ws", params={"repo": "../etc"}, headers=tenant_headers
    )
    assert resp.status_code == 422
