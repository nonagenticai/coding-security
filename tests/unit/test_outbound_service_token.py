"""Every sibling call must carry this service's own licence in ``Authorization``.

coding-security talks to coding-containers and coding-github on nine code paths,
and until now each one sent a **bare** ``X-Tenant-Id``. That is not a credential:
it worked only because those callees still trust the header when the request
arrives from the pod CIDR. The moment a callee runs with
``TRUST_TENANT_HEADER=false``, a bare header is refused — and in this service a
refusal is not visible as a refusal. ``container_registry`` turns any HTTPError
into ``None`` ("container not found"), ``_resolve_container_file_paths`` used to
turn it into ``[]`` ("no vulnerabilities"). A dropped credential therefore shows
up as a *clean scan*, which is the worst possible failure mode for a security
service.

So these tests assert on what reached the wire, via ``httpx.MockTransport``, and
they assert two things at once on every path:

* ``Authorization: Bearer <token>`` carries **our** identity, and
* ``X-Tenant-Id`` still carries the **customer's** tenant.

The second assertion is not redundant. Folding the credential into
``X-Tenant-Id`` — the shortcut some fleet clients took — makes the callee resolve
the tenant from our token and collapses every customer into
``svc-coding-security``'s own tenant. Sending the token is only correct if the
tenant survives beside it.
"""

from __future__ import annotations

import json

import httpx
import pytest
from coding_client.auth.outbound import TenantMissingError

from clients.containers_client import ContainersClient
from clients.github_client import GithubClient
from clients.outbound import optional_sibling_headers, sibling_headers
from models.container_models import ContainerInfo, ContainerStatus
from services import scan_runner
from services.container_registry import ContainerMetadataRegistry

TOKEN = "svc-security-token-xyz"
TENANT = "0195f48b-d000-7000-8000-000000000001"


# ---------------------------------------------------------------------------
# Transport plumbing
# ---------------------------------------------------------------------------


def _install_async_transport(monkeypatch, responder) -> list[httpx.Request]:
    """Force every ``httpx.AsyncClient`` built anywhere onto a MockTransport.

    The call sites under test construct their own client inline
    (``async with httpx.AsyncClient(timeout=...)``), so there is no client
    object to hand a transport to. Wrapping the constructor keeps the real
    client — and therefore the real header merging — in the path; replacing the
    client with a stub would test the stub instead of the code.
    """
    seen: list[httpx.Request] = []
    real_cls = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responder(request)

    def _factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real_cls(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    return seen


def _install_sync_transport(monkeypatch, responder) -> list[httpx.Request]:
    """Same as :func:`_install_async_transport` for the synchronous registry path."""
    seen: list[httpx.Request] = []
    real_cls = httpx.Client

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responder(request)

    def _factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real_cls(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", _factory)
    return seen


def _json_ok(payload):
    return lambda _request: httpx.Response(200, json=payload)


def _remote_container() -> ContainerInfo:
    """A container whose codebase_path is not local → forces the remote path."""
    return ContainerInfo(
        container_name="victim",
        api_endpoint="http://containers.svc/api/containers/victim",
        codebase_path="/workspace-does-not-exist-locally",
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def _assert_vouches_for(request: httpx.Request, tenant: str = TENANT) -> None:
    """The credential and the asserted tenant must both be present, and distinct."""
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert request.headers["x-tenant-id"] == tenant


# ---------------------------------------------------------------------------
# clients/outbound.py — the single decision point
# ---------------------------------------------------------------------------


class TestOutboundHelpers:
    def test_the_token_is_read_per_call_not_frozen_at_import(self, monkeypatch):
        """A rotated secret must take effect without restarting the pod."""
        monkeypatch.setenv("CODING_SERVICE_TOKEN", "first")
        assert sibling_headers(TENANT, operation="op")["Authorization"] == "Bearer first"
        monkeypatch.setenv("CODING_SERVICE_TOKEN", "second")
        assert sibling_headers(TENANT, operation="op")["Authorization"] == "Bearer second"

    def test_a_missing_tenant_is_refused_never_defaulted(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        with pytest.raises(TenantMissingError):
            sibling_headers(None, operation="containers exec find victim")

    def test_an_absent_tenant_is_omitted_and_never_becomes_a_literal(self, monkeypatch):
        """``optional_`` means absent, not ``"anonymous"`` and not a default tenant."""
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        headers = optional_sibling_headers(None)
        assert "X-Tenant-Id" not in headers
        # Identity is still proven — that is not a claim about whose data we want.
        assert headers["Authorization"] == f"Bearer {TOKEN}"

    def test_an_empty_token_env_var_is_not_sent_as_a_bare_bearer(self, monkeypatch):
        """``Bearer `` is a malformed credential, not "no credential"."""
        monkeypatch.setenv("CODING_SERVICE_TOKEN", "")
        assert "Authorization" not in sibling_headers(TENANT, operation="op")


# ---------------------------------------------------------------------------
# clients/containers_client.py
# ---------------------------------------------------------------------------


class TestContainersClient:
    async def test_package_upgrade_vouches_for_the_customer_tenant(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_async_transport(monkeypatch, _json_ok({"ok": True}))

        await ContainersClient("http://containers:8691").package_upgrade(
            container_name="victim", tenant_id=TENANT, body={"packages": []}
        )

        _assert_vouches_for(seen[0])
        assert seen[0].headers["content-type"] == "application/json"

    async def test_exec_command_vouches_for_the_customer_tenant(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_async_transport(monkeypatch, _json_ok({"stdout": ""}))

        await ContainersClient("http://containers:8691").exec_command(
            container_name="victim", tenant_id=TENANT, command=["ls"]
        )

        _assert_vouches_for(seen[0])

    async def test_no_token_means_no_authorization_header_at_all(self, monkeypatch):
        """Absent is absent — never an empty or fabricated credential."""
        monkeypatch.delenv("CODING_SERVICE_TOKEN", raising=False)
        seen = _install_async_transport(monkeypatch, _json_ok({"ok": True}))

        await ContainersClient("http://containers:8691").package_upgrade(
            container_name="victim", tenant_id=TENANT, body={"packages": []}
        )

        assert "authorization" not in seen[0].headers
        assert seen[0].headers["x-tenant-id"] == TENANT


# ---------------------------------------------------------------------------
# clients/github_client.py
# ---------------------------------------------------------------------------


class TestGithubClient:
    async def test_apply_changes_vouches_for_the_customer_tenant(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_async_transport(monkeypatch, _json_ok({"ok": True}))

        await GithubClient("http://github:8692").apply_changes(
            tenant_id=TENANT,
            container_name="victim",
            branch_name="fix/cve",
            changes=[{"file_path": "a.py", "content": "x"}],
        )

        _assert_vouches_for(seen[0])

    async def test_create_pull_request_vouches_for_the_customer_tenant(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_async_transport(monkeypatch, _json_ok({"ok": True}))

        await GithubClient("http://github:8692").create_pull_request(
            tenant_id=TENANT,
            original_owner="o",
            original_repo="r",
            fork_owner="f",
            fork_repo="r",
            head_branch="fix/cve",
            base_branch="main",
            title="t",
            message="m",
        )

        _assert_vouches_for(seen[0])

    async def test_no_token_means_no_authorization_header_at_all(self, monkeypatch):
        monkeypatch.delenv("CODING_SERVICE_TOKEN", raising=False)
        seen = _install_async_transport(monkeypatch, _json_ok({"ok": True}))

        await GithubClient("http://github:8692").apply_changes(
            tenant_id=TENANT, container_name="victim", branch_name="b", changes=[]
        )

        assert "authorization" not in seen[0].headers


# ---------------------------------------------------------------------------
# services/container_registry.py — sync AND async halves
# ---------------------------------------------------------------------------


class TestContainerRegistry:
    def test_sync_lookup_vouches_for_the_customer_tenant(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_sync_transport(
            monkeypatch, _json_ok({"container": {"container_name": "victim"}})
        )

        ContainerMetadataRegistry().find_by_name("victim", tenant_id=TENANT)

        _assert_vouches_for(seen[0])

    async def test_async_lookup_vouches_for_the_customer_tenant(self, monkeypatch):
        """The async half is a separate implementation and drifts independently."""
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_async_transport(
            monkeypatch, _json_ok({"container": {"container_name": "victim"}})
        )

        await ContainerMetadataRegistry().find_by_name_async("victim", tenant_id=TENANT)

        _assert_vouches_for(seen[0])

    def test_an_unscoped_lookup_still_proves_identity(self, monkeypatch):
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)
        seen = _install_sync_transport(
            monkeypatch, _json_ok({"container": {"container_name": "victim"}})
        )

        ContainerMetadataRegistry().find_by_name("victim")

        assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"
        assert "x-tenant-id" not in seen[0].headers


# ---------------------------------------------------------------------------
# services/scan_runner.py — the durable-worker scan paths
# ---------------------------------------------------------------------------


class TestScanRunner:
    async def test_every_codebase_fetch_call_vouches_for_the_tenant(self, monkeypatch):
        """Covers BOTH exec calls: the ``find`` listing and the bulk reader.

        A credential dropped on only the second one would fetch a file list and
        then silently download nothing — an empty, "clean" scan.
        """
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)

        def _responder(request: httpx.Request) -> httpx.Response:
            command = json.loads(request.content)["command"]
            if command[0] == "find":
                return httpx.Response(200, json={"stdout": "/workspace/a.py\n"})
            return httpx.Response(200, json={"stdout": json.dumps({"/workspace/a.py": "x = 1"})})

        seen = _install_async_transport(monkeypatch, _responder)

        result = await scan_runner._materialize_codebase(_remote_container(), "victim", TENANT)
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)

        assert len(seen) >= 2, "expected a find call and at least one read call"
        for request in seen:
            _assert_vouches_for(request)

    async def test_every_manifest_fetch_call_vouches_for_the_tenant(self, monkeypatch):
        """Covers BOTH exec calls on the dependency path: ``find`` and ``cat``."""
        monkeypatch.setenv("CODING_SERVICE_TOKEN", TOKEN)

        def _responder(request: httpx.Request) -> httpx.Response:
            command = json.loads(request.content)["command"]
            if command[0] == "find":
                return httpx.Response(200, json={"stdout": "/workspace/requirements.txt\n"})
            return httpx.Response(200, json={"stdout": "requests==2.0.0"})

        seen = _install_async_transport(monkeypatch, _responder)

        temp_dir, _incomplete = await scan_runner.fetch_manifests_to_tempdir(
            "victim", "/workspace", TENANT
        )
        import shutil

        shutil.rmtree(temp_dir, ignore_errors=True)

        assert len(seen) >= 2, "expected a find call and at least one cat call"
        for request in seen:
            _assert_vouches_for(request)
