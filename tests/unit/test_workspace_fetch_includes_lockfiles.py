"""Regression: the workspace fetch behind ``syft dir:`` dropped lockfiles.

``_materialize_codebase`` lists /workspace with a ``find -name`` filter built
for source scanning. It matched ``requirements.txt`` and ``package.json`` but no
lockfile and no Go/Rust/Java/.NET/Ruby/PHP manifest, so a workspace SBOM
silently inventoried a fraction of the dependencies. The fake container below
evaluates the REAL ``find`` command against a fake workspace listing, so the
test fails whenever a manifest is not matched by the filter.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
from unittest.mock import patch

import pytest

from models.container_models import ContainerInfo, ContainerStatus
from services.dependency_extraction import DependencyExtractor
from services.scan_runner import _WORKSPACE_DEPENDENCY_MANIFESTS, _materialize_codebase

MANIFESTS = [
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "web/package.json",
    "web/package-lock.json",
    "web/yarn.lock",
    "web/pnpm-lock.yaml",
    "svc/go.mod",
    "svc/go.sum",
    "rs/Cargo.toml",
    "rs/Cargo.lock",
    "java/pom.xml",
    "java/build.gradle",
    "java/build.gradle.kts",
    "dotnet/App.csproj",
    "dotnet/packages.lock.json",
    "dotnet/packages.config",
    "rb/Gemfile",
    "rb/Gemfile.lock",
    "php/composer.json",
    "php/composer.lock",
]
NOT_FETCHED = ["README.md", "assets/logo.png", ".git/config", "node_modules/x/package.json"]

#: Files that carry secrets and MUST be fetched now that the dot-space
#: exclusion is allowlist-aware (CI definitions + dotenv files).
SECRET_BEARING = [
    ".github/workflows/ci.yml",
    ".gitlab-ci.yml",
    ".pre-commit-config.yaml",
    ".env",
    "svc/.env",
    "svc/deep/.env.production",
]
#: Nested CI definitions and composite actions: the local walk admits these, so
#: the remote find allowlist must admit them too.
NESTED_CI_FILES = [
    ".github/actions/setup/action.yml",
    "frontend/.github/workflows/ci.yml",
    "frontend/.github/actions/setup/action.yml",
    ".circleci/config.yml",
    "frontend/.circleci/config.yml",
    ".gitlab/ci/test.yml",
    "frontend/.gitlab/ci/test.yml",
    "frontend/.gitlab-ci.yml",
    "frontend/.pre-commit-config.yaml",
]
#: Web-component source the discovery lists previously omitted.
WEB_COMPONENTS = [
    "web/App.jsx",
    "web/App.tsx",
    "web/App.vue",
    "web/App.svelte",
    "web/index.mjs",
    "web/index.cjs",
]
#: Hidden paths that stay excluded: only the CI/dotenv allowlist is admitted.
STILL_EXCLUDED = [
    ".github/dependabot.yml",  # matches *.yml, but is not a workflow/action file
    ".git/config.py",
    ".venv/lib/python3.14/site-packages/pkg.json",
    ".repos/o__src/package.json",
    "frontend/.next/server/page.py",
]


def _find(command: list[str], listing: list[str]) -> list[str]:
    """Evaluate the REAL ``find`` argv against a fake workspace listing.

    Parses the primaries the scanner emits — ``-name``, ``-path``, ``-type``,
    ``-not``, parenthesised groups and ``-o`` (with implicit ``-a``) — so this
    exercises the actual command string instead of re-deriving its intent.
    ``*`` crosses ``/`` in ``-path`` and in :func:`fnmatch.fnmatchcase`, as it
    does in find.
    """
    tokens = command[2:]  # after "find" and the (absolute) start path
    hits: list[str] = []
    for rel in listing:
        path = f"/workspace/{rel}"
        name = os.path.basename(path)

        def parse_or(i: int) -> tuple[bool, int]:
            value, i = parse_and(i)
            while i < len(tokens) and tokens[i] == "-o":
                right, i = parse_and(i + 1)
                value = value or right
            return value, i

        def parse_and(i: int) -> tuple[bool, int]:
            value, i = parse_factor(i)
            while i < len(tokens) and tokens[i] not in ("-o", ")"):
                right, i = parse_factor(i)
                value = value and right
            return value, i

        def parse_factor(i: int) -> tuple[bool, int]:
            token = tokens[i]
            if token == "-not":
                value, i = parse_factor(i + 1)
                return not value, i
            if token == "(":
                value, i = parse_or(i + 1)
                assert tokens[i] == ")"
                return value, i + 1
            if token == "-name":
                return fnmatch.fnmatchcase(name, tokens[i + 1]), i + 2
            if token == "-path":
                return fnmatch.fnmatchcase(path, tokens[i + 1]), i + 2
            if token == "-type":
                return True, i + 2  # every listing row is a regular file
            raise AssertionError(f"unparsed find primary: {token!r}")

        matched, _ = parse_or(0)
        if matched:
            hits.append(path)
    return hits


class _Resp:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.content = b"{}"
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def _client(listing: list[str]):
    class _FakeAsyncClient:
        is_closed = False

        async def aclose(self):
            return None

        async def request(self, _method, _url, **kwargs):
            cmd = kwargs["json"]["command"]
            if cmd[0] == "find":
                return _Resp({"stdout": "\n".join(_find(cmd, listing))})
            return _Resp({"stdout": json.dumps({p: f"# {p}\n" for p in cmd[4:]})})

    return _FakeAsyncClient()


@pytest.mark.asyncio
async def test_dependency_manifests_and_lockfiles_are_fetched():
    ci = ContainerInfo(
        container_name="ws",
        api_endpoint="http://x",
        codebase_path="/workspace",
        repo_url="https://example.invalid/r.git",
        branch="main",
        status=ContainerStatus.RUNNING,
    )
    with patch("httpx.AsyncClient", return_value=_client(MANIFESTS + NOT_FETCHED)):
        result = await _materialize_codebase(ci, "ws", "tenant-1")
    try:
        assert result.temp_dir is not None
        assert result.incomplete is False
        missing = [m for m in MANIFESTS if not os.path.isfile(os.path.join(result.temp_dir, m))]
        assert missing == []
        # Control: the filter is still a filter.
        for rel in NOT_FETCHED:
            assert not os.path.exists(os.path.join(result.temp_dir, rel)), rel
    finally:
        if result.temp_dir:
            shutil.rmtree(result.temp_dir, ignore_errors=True)


def test_the_fetch_list_and_the_extractor_registry_are_the_same_vocabulary():
    """A format the extractor registers MUST be fetched — and vice versa.

    Two hand-maintained lists is exactly how ``packages.config``'s parser
    shipped without a fetch entry: the parser was dead on every remote (k8s)
    scan, and the "one list" claim was false. Pinning the two sets together
    makes an added-only-on-one-side format fail here.
    """
    extractor_formats = (
        {name for name, _parser, _eco in DependencyExtractor._LOCKFILE_PARSERS}
        | {pattern for pattern, _parser, _eco in DependencyExtractor._MANIFEST_PARSERS}
        | {pattern for pattern, _eco in DependencyExtractor._UNPARSED_MANIFESTS}
    )
    fetched = set(_WORKSPACE_DEPENDENCY_MANIFESTS)

    assert extractor_formats - fetched == set(), "parsed or reported, but never fetched"
    assert fetched - extractor_formats == set(), "fetched, but no parser or unparsed entry"


@pytest.mark.asyncio
async def test_ci_workflows_and_dotenv_files_are_fetched():
    """Secrets in CI definitions / dotenv files are covered by the remote fetch.

    The old ``find`` filter dropped every hidden path, so a secret in
    ``.github/workflows/ci.yml`` or ``.env`` never reached detect-secrets. The
    argv is evaluated (not pattern-matched) so nested workflows, composite
    actions and the newly discovered web-component sources are all proven.
    """
    fetched = SECRET_BEARING + NESTED_CI_FILES + WEB_COMPONENTS
    ci = ContainerInfo(
        container_name="ws",
        api_endpoint="http://x",
        codebase_path="/workspace",
        repo_url="https://example.invalid/r.git",
        branch="main",
        status=ContainerStatus.RUNNING,
    )
    with patch("httpx.AsyncClient", return_value=_client(fetched + STILL_EXCLUDED)):
        result = await _materialize_codebase(ci, "ws", "tenant-1")
    try:
        assert result.temp_dir is not None
        assert result.incomplete is False
        for rel in fetched:
            assert os.path.isfile(os.path.join(result.temp_dir, rel)), rel
        # Control: the dot-space is still filtered, just not blanket-excluded.
        for rel in STILL_EXCLUDED:
            assert not os.path.exists(os.path.join(result.temp_dir, rel)), rel
    finally:
        if result.temp_dir:
            shutil.rmtree(result.temp_dir, ignore_errors=True)


def test_find_command_allowlists_nested_ci_paths():
    """The raw argv keeps nested CI/workflow/action paths past the dot filter."""
    from services.scan_runner import _workspace_find_command

    command = _workspace_find_command("/workspace")
    for pattern in (
        "/workspace/*/.github/workflows/*",
        "/workspace/*/.github/actions/*",
        "/workspace/.github/actions/*",
        "/workspace/*/.circleci/config.yml",
        "/workspace/*/.gitlab/ci/*",
        "/workspace/*/.gitlab-ci.yml",
    ):
        assert "-path" in command
        assert pattern in command
