"""Tests for /api/dependencies/{container}/upgrade and /upgrade-major.

The orchestrator delegates to coding-containers — these tests mock at the
``ContainersClient`` boundary so we don't need a live containers service.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

from models.container_models import ContainerInfo, ContainerStatus


@asynccontextmanager
async def _fake_async_cm():
    """Stand-in for the ``resolve_repo_path`` async context manager."""
    from routers.dependencies import ResolvedRepo

    yield ResolvedRepo(Path("/tmp"), False)


def _ci(name="my-repo") -> ContainerInfo:
    return ContainerInfo(
        container_name=name,
        api_endpoint="http://localhost:8080",
        codebase_path="/workspace",
        repo_url="https://github.com/acme/my-repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def _containers_upgrade_response(
    *,
    manager: str = "uv",
    mode: str = "in-range",
    before: dict[str, str] | None = None,
    after: dict[str, str] | None = None,
    exit_code: int = 0,
) -> dict:
    return {
        "manager": manager,
        "mode": mode,
        "project_path": ".",
        "dry_run": False,
        "exit_code": exit_code,
        "stdout": "Resolved 1 package.",
        "stderr": "",
        "duration_seconds": 0.42,
        "commands_executed": [["uv", "lock", "--upgrade-package", "httpx"]],
        "manifest_files_before": before
        or {
            "pyproject.toml": '[project]\ndependencies = ["httpx>=0.25,<1.0"]\n',
            "uv.lock": '[[package]]\nname = "httpx"\nversion = "0.27.0"\n',
        },
        "manifest_files_after": after
        or {
            "pyproject.toml": '[project]\ndependencies = ["httpx>=0.25,<1.0"]\n',
            "uv.lock": '[[package]]\nname = "httpx"\nversion = "0.27.2"\n',
        },
    }


# ⛔ THIS IS THE SHAPE coding-github ACTUALLY RETURNS, and pinning it here is the point.
#
# These mocks used to return ``{"branch_url": "http://gh/branch"}`` — a key
# ApplyChangesResponse (coding-github src/schemas/github_api_models.py:416) HAS NEVER HAD.
# Its fields are branch_name / commit_sha / changes_applied / no_changes / fork_url /
# authoring_identity. coding-security read ``branch_url or commit_url``, so on the real
# service commit_url was not "null sometimes" — it was STRUCTURALLY ALWAYS null, and every
# test passed because the fixture invented the field the code was reaching for. The bug
# and its fixture agreed with each other, which is why five green tests never saw it.
# It surfaced only in production, as enterprise_mcp_server#90: a real three-file diff, a
# real PR, and a card reporting ``"commit_url": null``.
_APPLY_CHANGES_OK = {
    "status": "success",
    "message": "Applied 3 change(s) to branch 'aa/chore'",
    "branch_name": "aa/chore",
    # A deliberately LOW-ENTROPY, full-length sha. The short mixed-hex value used here
    # first tripped detect-secrets as a "Hex High Entropy String", and baselining a value
    # that is not a secret would teach the baseline to carry noise — the shape that makes a
    # real finding easy to wave through. Note the literal is not repeated here either:
    # detect-secrets reads comments, so naming the value would re-trip the very gate.
    "commit_sha": "1111111111111111111111111111111111111111",
    "changes_applied": 3,
    "no_changes": False,
    "fork_url": "https://github.com/nonagenticai/enterprise_mcp_server/tree/aa/chore",
    "authoring_identity": "app/code-graph-helper-app",
}
_APPLY_CHANGES_NO_OP = {
    **_APPLY_CHANGES_OK,
    "commit_sha": None,
    "changes_applied": 0,
    "no_changes": True,
    "message": "No changes to apply on branch 'aa/chore'",
}


class TestInRangeUpgradeEndpoint:
    def test_404_when_container_missing(self, test_client, tenant_headers):
        resp = test_client.post(
            "/api/dependencies/nonexistent/upgrade",
            json={"packages": [{"name": "httpx"}]},
            headers=tenant_headers,
        )
        assert resp.status_code == 404

    def test_happy_path_in_range_uv(self, test_client, tenant_headers):
        upgrade_resp = _containers_upgrade_response()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade",
                json={"packages": [{"name": "httpx"}], "manager": "uv"},
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["manager"] == "uv"
        assert body["mode"] == "in-range"
        assert body["exit_code"] == 0
        # Lockfile diff captured.
        diffs = body["manifest_diffs"]
        assert any(d["path"] == "uv.lock" for d in diffs)
        # Per-package result populated.
        names = {r["name"] for r in body["results"]}
        assert "httpx" in names
        result = next(r for r in body["results"] if r["name"] == "httpx")
        assert result["previous_version"] == "0.27.0"
        assert result["new_version"] == "0.27.2"

    def test_auto_detect_manager_from_uv_lock(self, test_client, tenant_headers):
        """Caller omits ``manager``; orchestrator picks uv from uv.lock presence."""
        upgrade_resp = _containers_upgrade_response()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ) as mock_pu,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade",
                json={"packages": [{"name": "httpx"}]},
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        # The body sent to coding-containers should carry the detected manager.
        kwargs = mock_pu.call_args.kwargs
        assert kwargs["body"]["manager"] == "uv"

    def test_commit_requires_branch_name(self, test_client, tenant_headers):
        resp = test_client.post(
            "/api/dependencies/my-repo/upgrade",
            json={"packages": [{"name": "httpx"}], "commit": True},
            headers=tenant_headers,
        )
        assert resp.status_code == 400

    def test_open_pr_requires_commit(self, test_client, tenant_headers):
        resp = test_client.post(
            "/api/dependencies/my-repo/upgrade",
            json={
                "packages": [{"name": "httpx"}],
                "open_pr": True,
                "branch_name": "deps/x",
            },
            headers=tenant_headers,
        )
        assert resp.status_code == 400


class TestCrossMajorUpgradeEndpoint:
    def test_fastmcp_3_0_0_cross_major(self, test_client, tenant_headers, monkeypatch):
        """The headline scenario: pyproject.toml has ``fastmcp>=2.13.0,<3.0.0`` and
        the user wants 3.0.0 — only /upgrade-major can cross that ceiling.
        """
        before_pyproject = '[project]\ndependencies = ["fastmcp>=2.13.0,<3.0.0"]\n'
        after_pyproject = '[project]\ndependencies = ["fastmcp>=3.0.0,<4.0.0"]\n'
        before_lock = '[[package]]\nname = "fastmcp"\nversion = "2.14.2"\n'
        after_lock = '[[package]]\nname = "fastmcp"\nversion = "3.0.0"\n'

        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": before_pyproject, "uv.lock": before_lock},
            after={"pyproject.toml": after_pyproject, "uv.lock": after_lock},
        )
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [{"name": "fastmcp", "target_version": "3.0.0"}],
                    "manager": "uv",
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "cross-major"
        # Both manifests changed.
        paths = {d["path"] for d in body["manifest_diffs"]}
        assert {"pyproject.toml", "uv.lock"} <= paths
        # Per-package result reflects both version and constraint change.
        result = next(r for r in body["results"] if r["name"] == "fastmcp")
        assert result["previous_version"] == "2.14.2"
        assert result["new_version"] == "3.0.0"
        assert result["previous_constraint"] == ">=2.13.0,<3.0.0"
        assert result["new_constraint"] == ">=3.0.0,<4.0.0"

    def test_commit_sends_file_path_to_apply_changes(
        self, test_client, tenant_headers, monkeypatch
    ):
        """Regression: coding-github's GitHubFileChangeOperation requires
        ``file_path`` (no ``path`` alias). The outbound apply-changes payload
        must key each change on ``file_path`` or coding-github returns
        ``422 body.changes.0.file_path "Field required"`` and no PR is opened.
        """
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": '[project]\ndependencies = ["fastmcp>=2.13.0,<3.0.0"]\n'},
            after={"pyproject.toml": '[project]\ndependencies = ["fastmcp>=3.0.0,<4.0.0"]\n'},
        )
        # The github client is only built when github_service_url is configured.
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_OK),
            ) as mock_apply,
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(return_value={"pr_url": "http://gh/pull/1"}),
            ) as mock_pr,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [{"name": "fastmcp", "target_version": "3.0.0"}],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "aa/my-repo",
                    "open_pr": True,
                    "pr_title": "deps: upgrade fastmcp",
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        assert mock_apply.called, "apply_changes was not called on a successful commit"
        changes = mock_apply.call_args.kwargs["changes"]
        assert changes, "no changes were sent to apply_changes"
        for change in changes:
            assert "file_path" in change, f"change missing file_path key: {change}"
            assert "path" not in change, f"change still uses legacy path key: {change}"
            assert "content" in change
        assert any(c["file_path"] == "pyproject.toml" for c in changes)
        assert mock_pr.called
        assert resp.json()["pr_url"] == "http://gh/pull/1"

    def test_commit_url_is_derived_from_the_keys_apply_changes_actually_returns(
        self, test_client, tenant_headers, monkeypatch
    ):
        """A real commit must produce a real commit_url.

        THE DEFECT. `_maybe_commit_and_pr` read ``branch_url or commit_url`` from the
        apply-changes response. coding-github's ApplyChangesResponse emits NEITHER — its
        fields are branch_name / commit_sha / changes_applied / no_changes / fork_url —
        so commit_url was not "null sometimes", it was STRUCTURALLY ALWAYS null on every
        successful commit this service ever made. Production surfaced it as
        enterprise_mcp_server#90: a real three-file diff, a real PR, and a card reporting
        ``"commit_url": null``.

        WHY NO TEST CAUGHT IT. The mocks returned ``{"branch_url": "http://gh/branch"}`` —
        a shape the real service never produces. The fixture agreed with the bug, so five
        green tests looked straight at it and saw nothing. This test runs against
        `_APPLY_CHANGES_OK`, which mirrors the REAL response, and therefore FAILS against
        the pre-fix code.
        """
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": '[project]\ndependencies = ["fastmcp==3.4.2"]\n'},
            after={"pyproject.toml": '[project]\ndependencies = ["fastmcp==3.4.7"]\n'},
        )
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_OK),
            ),
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(return_value={"pr_url": "http://gh/pull/90", "pr_number": 90}),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [{"name": "fastmcp", "target_version": "3.4.7"}],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "aa/chore",
                    "open_pr": True,
                    "pr_title": "chore: dependency upgrade",
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # The exact URL, not merely "not null" — a truthy-but-wrong value (the branch
        # tree URL, say) is the same class of lie the null was.
        assert body["commit_url"] == (
            "https://github.com/nonagenticai/enterprise_mcp_server/commit/"
            "1111111111111111111111111111111111111111"
        ), body["commit_url"]
        # A produced commit_url must NOT also carry a skip reason; the two are exclusive.
        assert body["commit_skip_reason"] is None, body["commit_skip_reason"]

    def test_a_no_op_apply_names_its_refusal_instead_of_returning_a_bare_null(
        self, test_client, tenant_headers, monkeypatch
    ):
        """The other half: when there IS no commit, say which of the four reasons it was.

        `_maybe_commit_and_pr` returned a bare ``(None, None, None)`` for four genuinely
        different situations — upgrade failed / commit not requested / nothing to commit /
        apply-changes produced no sha — so a card could print ``commit_url: null`` and had
        no way to say whether the work was refused, skipped, or silently lost. That is the
        'a refusal a client cannot act on' shape that has cost this programme three
        sessions. Here coding-github reports its typed benign no-op (no_changes=True), and
        the response must NAME it.
        """
        target = '[project]\ndependencies = ["fastmcp==3.4.7"]\n'
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": target},
            after={"pyproject.toml": target},
        )
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_NO_OP),
            ),
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(return_value={"pr_url": "http://gh/pull/91"}),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [{"name": "fastmcp", "target_version": "3.4.7"}],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "aa/chore",
                    "open_pr": True,
                    "pr_title": "chore: dependency upgrade",
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["commit_url"] is None
        assert body["commit_skip_reason"] == "no_changes_to_apply", body["commit_skip_reason"]
        # And no PR may be claimed off a commit that did not happen.
        assert body["pr_url"] is None, body["pr_url"]

    def test_commit_not_requested_is_distinguishable_from_nothing_to_commit(
        self, test_client, tenant_headers
    ):
        """The two reasons that used to be the same silent None.

        Without a github_service_url the client is absent, so this exercises the
        pre-apply gate: commit=False must name itself, and must not be confusable with a
        commit that was attempted and produced nothing.
        """
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": '[project]\ndependencies = ["fastmcp==3.4.2"]\n'},
            after={"pyproject.toml": '[project]\ndependencies = ["fastmcp==3.4.7"]\n'},
        )
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [{"name": "fastmcp", "target_version": "3.4.7"}],
                    "manager": "uv",
                    "commit": False,
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["commit_url"] is None
        assert body["commit_skip_reason"] == "commit_not_requested", body["commit_skip_reason"]

    def test_redrive_no_workspace_diff_still_opens_pr(
        self, test_client, tenant_headers, monkeypatch
    ):
        """Idempotency: re-driving the same version on a reused container makes
        the workspace before==after (empty workspace diff), which previously
        opened no PR. The fix applies the FULL post-upgrade manifest set onto a
        branch off base (coding-github is no-op-safe), so a PR is still opened.
        """
        target = '[project]\ndependencies = ["fastmcp==3.2.4"]\n'
        target_lock = '[[package]]\nname = "fastmcp"\nversion = "3.2.4"\n'
        # Workspace already at target on both sides ⇒ _compute_diffs == [].
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": target, "uv.lock": target_lock},
            after={"pyproject.toml": target, "uv.lock": target_lock},
        )
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_OK),
            ) as mock_apply,
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(return_value={"pr_url": "http://gh/pull/7"}),
            ) as mock_pr,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [
                        {"name": "fastmcp", "target_version": "3.2.4", "new_constraint": "==3.2.4"}
                    ],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "aa/my-repo",
                    "open_pr": True,
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Workspace diff is empty (already at target)...
        assert body["manifest_diffs"] == []
        # ...but the full post-upgrade manifest set was still applied (base-relative).
        assert mock_apply.called
        sent = {c["file_path"] for c in mock_apply.call_args.kwargs["changes"]}
        assert sent == {"pyproject.toml", "uv.lock"}
        # ...and a PR was opened/returned.
        assert mock_pr.called
        assert body["pr_url"] == "http://gh/pull/7"

    def test_cve_redrive_no_workspace_diff_still_opens_pr(
        self, test_client, tenant_headers, monkeypatch
    ):
        """CVE-path analog of the base-relative fix: the tournament reuses a
        candidate container whose workspace may already be at target (empty
        before/after ``manifest_diffs``). The upgrade-cves path previously left
        ``commit_url=null`` (legacy diff-gate) → no remote branch → the tournament
        winner PR failed. Now it applies the full post-upgrade manifest set onto a
        branch off base (base-relative), so apply_changes runs and a PR opens even
        with an empty workspace diff — the fix that unblocks larger repos."""
        # Analyzer sees the vulnerable version (2.6.2) so a fix (2.7.0) is planned
        # in-range; but the container workspace was already bumped to 2.7.0 by a
        # prior batch, so before == after ⇒ empty workspace diff (enterprise class).
        report = _risk_report(
            vulnerable_pkg_name="urllib3",
            installed_version="2.6.2",
            constraint=">=2.0.0",
            fixed_versions=["2.7.0"],
            severity="HIGH",
        )
        lock = '[[package]]\nname = "urllib3"\nversion = "2.7.0"\n'
        # before == after ⇒ workspace _compute_diffs == [] (the enterprise class).
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="in-range",
            before={"uv.lock": lock},
            after={"uv.lock": lock},
        )
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer.analyze",
                new=AsyncMock(return_value=report),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "uv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_OK),
            ) as mock_apply,
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(return_value={"pr_url": "http://gh/pull/9"}),
            ) as mock_pr,
            patch(
                "routers.dependencies.resolve_repo_path",
                new=lambda c, t: _fake_async_cm(),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-cves",
                json={
                    "min_severity": "LOW",
                    "allow_major": False,
                    "commit": True,
                    "branch_name": "aa/chore-my-repo",
                    "open_pr": True,
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Empty workspace diff...
        assert body["manifest_diffs"] == []
        # ...but base-relative commit still applied the manifest set and opened a PR
        # (previously commit_url was null → no branch → no winner PR).
        assert mock_apply.called, "apply_changes not called — base-relative CVE commit regressed"
        assert mock_pr.called
        assert body["pr_url"] == "http://gh/pull/9"

    def test_draft_flag_threaded_and_pr_number_surfaced(
        self, test_client, tenant_headers, monkeypatch
    ):
        """draft=True reaches coding-github and pr_number is surfaced in the response."""
        target = '[project]\ndependencies = ["fastmcp==3.2.4"]\n'
        target_lock = '[[package]]\nname = "fastmcp"\nversion = "3.2.4"\n'
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": target, "uv.lock": target_lock},
            after={"pyproject.toml": target, "uv.lock": target_lock},
        )
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_OK),
            ),
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(
                    return_value={"pr_url": "http://gh/pull/9", "pr_number": 9, "draft": True}
                ),
            ) as mock_pr,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [
                        {"name": "fastmcp", "target_version": "3.2.4", "new_constraint": "==3.2.4"}
                    ],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "aa/my-repo",
                    "open_pr": True,
                    "draft": True,
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert mock_pr.called
        assert mock_pr.call_args.kwargs["draft"] is True
        assert body["pr_url"] == "http://gh/pull/9"
        assert body["pr_number"] == 9

    def test_no_commits_between_base_and_head_yields_no_pr(
        self, test_client, tenant_headers, monkeypatch
    ):
        """When the post-upgrade manifests match base (nothing to PR),
        coding-github surfaces GitHub's 'No commits between' 422 — coding-security
        treats it as a benign no-op (pr_url=None), not an error.
        """
        from clients.github_client import GithubClientError

        target = '[project]\ndependencies = ["fastmcp==3.2.4"]\n'
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={"pyproject.toml": target},
            after={"pyproject.toml": target},
        )
        monkeypatch.setenv("GITHUB_SERVICE_URL", "http://coding-github.test:8692")
        from config.settings import get_settings

        get_settings.cache_clear()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(return_value=_APPLY_CHANGES_OK),
            ),
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(
                    side_effect=GithubClientError(
                        422, "create-pull-request -> 422: No commits between main and aa/my-repo"
                    )
                ),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-major",
                json={
                    "packages": [
                        {"name": "fastmcp", "target_version": "3.2.4", "new_constraint": "==3.2.4"}
                    ],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "aa/my-repo",
                    "open_pr": True,
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["pr_url"] is None

    def test_rejects_empty_packages(self, test_client, tenant_headers):
        resp = test_client.post(
            "/api/dependencies/my-repo/upgrade-major",
            json={"packages": []},
            headers=tenant_headers,
        )
        assert resp.status_code in (400, 422)


# ============================================================================
# CVE-driven, add, remove, replace
# ============================================================================


from datetime import UTC, datetime  # noqa: E402

from models.architecture_models import (  # noqa: E402
    DependencyRiskReport,
    DependencyRiskSummary,
    Vulnerability,
)
from models.package_manager_models import (  # noqa: E402
    ExternalPackage,
    LanguagePackageManager,
)


def _risk_report(
    *,
    vulnerable_pkg_name: str = "fastmcp",
    installed_version: str = "2.14.2",
    constraint: str = ">=2.13.0,<3.0.0",
    fixed_versions: list[str] | None = None,
    severity: str = "CRITICAL",
) -> DependencyRiskReport:
    """Build a minimal report with one vulnerable Python package."""
    return DependencyRiskReport(
        codebase_id="my-repo",
        generated_at=datetime.now(UTC).isoformat(),
        packages=[
            ExternalPackage(
                name=vulnerable_pkg_name,
                version=constraint,
                current_version=installed_version,
                manager=LanguagePackageManager.UV,
                ecosystem="pypi",
            )
        ],
        vulnerabilities=[
            Vulnerability(
                id="CVE-2026-1234",
                severity=severity,
                summary="hypothetical RCE",
                details="",
                affected_versions=[installed_version],
                fixed_versions=fixed_versions or ["3.0.0"],
                references=[],
                published_date="",
                modified_date="",
                package_name=vulnerable_pkg_name,
            )
        ],
        risk_score=8.0,
        summary=DependencyRiskSummary(
            total_packages=1,
            vulnerable_packages=1,
            total_vulnerabilities=1,
            critical_vulnerabilities=1 if severity == "CRITICAL" else 0,
            high_vulnerabilities=1 if severity == "HIGH" else 0,
            moderate_vulnerabilities=0,
            low_vulnerabilities=0,
        ),
    )


class TestUpgradeCvesEndpoint:
    def test_critical_cve_crosses_major_when_allow_major_true(self, test_client, tenant_headers):
        """The canonical case: fastmcp 2.14.2 with CVE fix in 3.0.0,
        constraint <3.0.0. allow_major defaults to True so the route
        should pick cross-major and bump."""
        report = _risk_report()
        upgrade_resp = _containers_upgrade_response(
            manager="uv",
            mode="cross-major",
            before={
                "pyproject.toml": '[project]\ndependencies = ["fastmcp>=2.13.0,<3.0.0"]\n',
                "uv.lock": '[[package]]\nname = "fastmcp"\nversion = "2.14.2"\n',
            },
            after={
                "pyproject.toml": '[project]\ndependencies = ["fastmcp>=3.0.0,<4.0.0"]\n',
                "uv.lock": '[[package]]\nname = "fastmcp"\nversion = "3.0.0"\n',
            },
        )
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer.analyze",
                new=AsyncMock(return_value=report),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=upgrade_resp),
            ) as mock_pu,
            # Path resolution short-circuits the live container exec path.
            # ``resolve_repo_path`` is an async context manager; build one
            # on the fly that just yields a dummy path.
            patch(
                "routers.dependencies.resolve_repo_path",
                new=lambda c, t: _fake_async_cm(),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-cves",
                json={"min_severity": "HIGH"},
                headers=tenant_headers,
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "upgrade-cves"
        assert body["cve_summary"]["fixed"] == 1
        # The right batch was sent to coding-containers.
        kwargs = mock_pu.call_args.kwargs
        assert kwargs["body"]["mode"] == "cross-major"
        major_specs = kwargs["body"]["major_specs"]
        assert any(s["name"] == "fastmcp" and s["target_version"] == "3.0.0" for s in major_specs)
        # PackageResult carries the CVE id.
        result = next(r for r in body["results"] if r["name"] == "fastmcp")
        assert "CVE-2026-1234" in result["fixed_cves"]

    def test_analyzer_degraded_flag_is_not_overwritten(self, test_client, tenant_headers):
        """analyze() flags an OSV lookup failure; a complete repo fetch must OR into
        it, never reset it to False (coding-security#103)."""
        report = _risk_report()
        report.scan_degraded = True
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer.analyze",
                new=AsyncMock(return_value=report),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=_containers_upgrade_response(mode="cross-major")),
            ),
            patch(
                "routers.dependencies.resolve_repo_path",
                new=lambda c, t: _fake_async_cm(),  # ResolvedRepo(..., incomplete=False)
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-cves",
                json={"min_severity": "HIGH"},
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        assert report.scan_degraded is True

    def test_exact_pin_same_major_rewrites_constraint_and_opens_path(
        self, test_client, tenant_headers
    ):
        """Regression: a DIRECT dep pinned exactly (``requests==2.31.0``) with a
        same-major fix (2.32.0). The analyzer reports the bare RESOLVED version
        (``2.31.0``) as the constraint, so ``constraint_allows`` is permissive →
        the in-range batch runs ``uv lock --upgrade-package`` which CANNOT move
        an exact pin (manifests unchanged). The fix must detect the no-move and
        re-dispatch via the constraint-rewrite (cross-major) path with
        ``>=2.32.0`` so the version actually moves and a real diff/PR results —
        instead of the old false ``success`` with no change and no PR."""
        report = _risk_report(
            vulnerable_pkg_name="requests",
            installed_version="2.31.0",
            constraint="2.31.0",  # bare resolved version, as the live analyzer emits
            fixed_versions=["2.32.0"],
            severity="MODERATE",
        )
        in_range_noop = _containers_upgrade_response(
            mode="in-range",
            before={
                "pyproject.toml": '[project]\ndependencies = ["requests==2.31.0"]\n',
                "uv.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
            },
            after={  # uv lock could not move the exact pin → identical
                "pyproject.toml": '[project]\ndependencies = ["requests==2.31.0"]\n',
                "uv.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
            },
        )
        rewrite_moved = _containers_upgrade_response(
            mode="cross-major",
            before={
                "pyproject.toml": '[project]\ndependencies = ["requests==2.31.0"]\n',
                "uv.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
            },
            after={  # uv add requests>=2.32.0 rewrote pyproject + moved the lock
                "pyproject.toml": '[project]\ndependencies = ["requests>=2.32.0"]\n',
                "uv.lock": '[[package]]\nname = "requests"\nversion = "2.32.0"\n',
            },
        )
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer.analyze",
                new=AsyncMock(return_value=report),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(side_effect=[in_range_noop, rewrite_moved]),
            ) as mock_pu,
            patch(
                "routers.dependencies.resolve_repo_path",
                new=lambda c, t: _fake_async_cm(),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-cves",
                json={"min_severity": "LOW", "allow_major": False},
                headers=tenant_headers,
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cve_summary"]["fixed"] == 1
        assert body["cve_summary"]["skipped_needs_major"] == 0
        # Two dispatches: the in-range no-op, then the constraint-rewrite.
        assert mock_pu.call_count == 2
        rewrite_call = mock_pu.call_args_list[1].kwargs["body"]
        assert rewrite_call["mode"] == "cross-major"
        assert any(
            s["name"] == "requests" and s["new_constraint"] == ">=2.32.0"
            for s in rewrite_call["major_specs"]
        )
        # The version actually moved → real diff → result reflects the bump.
        result = next(r for r in body["results"] if r["name"] == "requests")
        assert result["previous_version"] == "2.31.0"
        assert result["new_version"] == "2.32.0"
        assert result["success"] is True
        assert any(d["path"] == "uv.lock" for d in body["manifest_diffs"])

    def test_allow_major_false_skips_major_bumps(self, test_client, tenant_headers):
        """allow_major=false: same scenario, but the cross-major bump is refused."""
        report = _risk_report()
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer.analyze",
                new=AsyncMock(return_value=report),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(),
            ) as mock_pu,
            patch(
                "routers.dependencies.resolve_repo_path",
                new=lambda c, t: _fake_async_cm(),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-cves",
                json={"min_severity": "HIGH", "allow_major": False},
                headers=tenant_headers,
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cve_summary"]["fixed"] == 0
        assert body["cve_summary"]["skipped_needs_major"] == 1
        # Crucially: no upstream call was made because nothing was dispatchable.
        mock_pu.assert_not_called()
        result = next(r for r in body["results"] if r["name"] == "fastmcp")
        assert result["success"] is False
        assert "allow_major" in (result["error"] or "")

    def test_unresolvable_lock_reports_zero_fixed_not_planned(self, test_client, tenant_headers):
        """Honesty gap: a package is PLANNED (in-range, constraint allows) but the
        in-container ``uv lock`` cannot resolve (e.g. the repo's own constraints are
        internally unsatisfiable → "No solution found", exit_code != 0). The apply
        changes nothing, no commit/PR happens — so ``cve_summary.fixed`` must be 0
        (the applied count), NOT 1 (the planned count). The resolver error is on
        ``exit_code`` + ``stderr`` + the per-package result."""
        report = _risk_report(
            vulnerable_pkg_name="urllib3",
            installed_version="2.0.0",
            constraint=">=2.0.0",  # constraint allows the fix → planned in-range
            fixed_versions=["2.0.7"],
            severity="HIGH",
        )
        # uv lock failed: exit_code != 0, manifests unchanged.
        unresolvable = _containers_upgrade_response(
            mode="in-range",
            before={"uv.lock": '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'},
            after={"uv.lock": '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'},
            exit_code=1,
        )
        unresolvable["stderr"] = "No solution found when resolving dependencies"
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer.analyze",
                new=AsyncMock(return_value=report),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "uv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_upgrade",
                new=AsyncMock(return_value=unresolvable),
            ),
            patch(
                "routers.dependencies.resolve_repo_path",
                new=lambda c, t: _fake_async_cm(),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/upgrade-cves",
                json={"min_severity": "LOW", "allow_major": False},
                headers=tenant_headers,
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        # The lie would be fixed==1 (planned); the truth is 0 (nothing applied).
        assert body["cve_summary"]["fixed"] == 0
        assert body["exit_code"] != 0
        assert "No solution found" in (body["stderr"] or "")
        result = next(r for r in body["results"] if r["name"] == "urllib3")
        assert result["success"] is False
        # No PR/commit on a failed apply.
        assert body.get("pr_url") in (None, "")


class TestAddEndpoint:
    def test_add_dependency_happy_path(self, test_client, tenant_headers):
        modify_resp = {
            "manager": "uv",
            "action": "add",
            "project_path": ".",
            "dry_run": False,
            "exit_code": 0,
            "stdout": "Added structlog 24.4.0",
            "stderr": "",
            "duration_seconds": 0.5,
            "commands_executed": [["uv", "add", "structlog==24.4.0"]],
            "manifest_files_before": {
                "pyproject.toml": '[project]\ndependencies = ["httpx>=0.25"]\n',
                "uv.lock": "",
            },
            "manifest_files_after": {
                "pyproject.toml": '[project]\ndependencies = ["httpx>=0.25", "structlog==24.4.0"]\n',
                "uv.lock": '[[package]]\nname = "structlog"\nversion = "24.4.0"\n',
            },
        }
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_modify",
                new=AsyncMock(return_value=modify_resp),
            ) as mock_pm,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/add",
                json={
                    "packages": [{"name": "structlog", "version": "24.4.0"}],
                    "manager": "uv",
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "add"
        assert any(d["path"] == "pyproject.toml" for d in body["manifest_diffs"])
        kwargs = mock_pm.call_args.kwargs
        assert kwargs["body"]["action"] == "add"
        assert kwargs["body"]["add_specs"][0]["name"] == "structlog"


class TestRemoveEndpoint:
    def test_remove_dependency_happy_path(self, test_client, tenant_headers):
        modify_resp = {
            "manager": "uv",
            "action": "remove",
            "project_path": ".",
            "dry_run": False,
            "exit_code": 0,
            "stdout": "Removed httpx",
            "stderr": "",
            "duration_seconds": 0.3,
            "commands_executed": [["uv", "remove", "httpx"]],
            "manifest_files_before": {
                "pyproject.toml": '[project]\ndependencies = ["httpx>=0.25"]\n',
            },
            "manifest_files_after": {
                "pyproject.toml": "[project]\ndependencies = []\n",
            },
        }
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_modify",
                new=AsyncMock(return_value=modify_resp),
            ),
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/remove",
                json={"packages": ["httpx"], "manager": "uv"},
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["mode"] == "remove"


class TestReplaceEndpoint:
    def test_replace_asyncpg_with_psycopg(self, test_client, tenant_headers):
        """asyncpg → psycopg with binary+pool extras. Verifies the right
        request shape was sent and the response carries replacement results.
        """
        modify_resp = {
            "manager": "uv",
            "action": "replace",
            "project_path": ".",
            "dry_run": False,
            "exit_code": 0,
            "stdout": "Removed asyncpg, added psycopg",
            "stderr": "",
            "duration_seconds": 1.1,
            "commands_executed": [
                ["uv", "remove", "asyncpg"],
                ["uv", "add", "psycopg[binary,pool]>=3.2,<4"],
            ],
            "manifest_files_before": {
                "pyproject.toml": '[project]\ndependencies = ["asyncpg>=0.29"]\n',
                "uv.lock": '[[package]]\nname = "asyncpg"\nversion = "0.29.0"\n',
            },
            "manifest_files_after": {
                "pyproject.toml": '[project]\ndependencies = ["psycopg[binary,pool]>=3.2,<4"]\n',
                "uv.lock": '[[package]]\nname = "psycopg"\nversion = "3.2.0"\n',
            },
        }
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\nuv.lock\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_modify",
                new=AsyncMock(return_value=modify_resp),
            ) as mock_pm,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/replace",
                json={
                    "replacements": [
                        {
                            "old": "asyncpg",
                            "new": "psycopg",
                            "new_constraint": ">=3.2,<4",
                            "extras": ["binary", "pool"],
                        }
                    ],
                    "manager": "uv",
                },
                headers=tenant_headers,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "replace"
        kwargs = mock_pm.call_args.kwargs
        cb = kwargs["body"]
        assert cb["action"] == "replace"
        assert cb["remove_names"] == ["asyncpg"]
        assert cb["add_specs"][0]["name"] == "psycopg"
        assert cb["add_specs"][0]["extras"] == ["binary", "pool"]

    def test_replace_atomicity_no_commit_on_partial_failure(self, test_client, tenant_headers):
        """If exit_code != 0 from coding-containers, the orchestrator must not
        attempt commit/PR — confirms a half-migration never ships."""
        modify_resp = {
            "manager": "uv",
            "action": "replace",
            "project_path": ".",
            "dry_run": False,
            "exit_code": 1,
            "stdout": "Removed asyncpg",
            "stderr": "ERROR: No matching distribution found for psycopg",
            "duration_seconds": 0.8,
            "commands_executed": [["uv", "remove", "asyncpg"], ["uv", "add", "psycopg@latest"]],
            "manifest_files_before": {
                "pyproject.toml": '[project]\ndependencies = ["asyncpg>=0.29"]\n',
            },
            "manifest_files_after": {
                "pyproject.toml": "[project]\ndependencies = []\n",  # half-applied
            },
        }
        with (
            patch(
                "services.container_registry.ContainerMetadataRegistry.get_container_async",
                new=AsyncMock(return_value=_ci()),
            ),
            patch(
                "clients.containers_client.ContainersClient.exec_command",
                new=AsyncMock(return_value={"stdout": "pyproject.toml\n", "exit_code": 0}),
            ),
            patch(
                "clients.containers_client.ContainersClient.package_modify",
                new=AsyncMock(return_value=modify_resp),
            ),
            patch(
                "clients.github_client.GithubClient.apply_changes",
                new=AsyncMock(),
            ) as mock_apply,
            patch(
                "clients.github_client.GithubClient.create_pull_request",
                new=AsyncMock(),
            ) as mock_pr,
        ):
            resp = test_client.post(
                "/api/dependencies/my-repo/replace",
                json={
                    "replacements": [{"old": "asyncpg", "new": "psycopg"}],
                    "manager": "uv",
                    "commit": True,
                    "branch_name": "deps/psycopg",
                    "open_pr": True,
                    "pr_title": "deps: migrate",
                },
                headers=tenant_headers,
            )
        # Endpoint returns 200 with exit_code=1 in the body — the caller can
        # see the failure. Importantly: no commit and no PR were attempted.
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["exit_code"] == 1
        # Either github_service_url was unconfigured (no client) or the helper
        # short-circuited on non-zero exit. Either way: apply_changes never
        # ran. (When unconfigured, the github_client is None so apply_changes
        # is never even reachable.)
        # We assert no commit was attempted regardless of why.
        if mock_apply.called:
            raise AssertionError("commit attempted despite exit_code=1 from coding-containers")
        if mock_pr.called:
            raise AssertionError("PR creation attempted despite exit_code=1")
