"""Regression tests for the container-fetch hardening on top of #62.

These cover three properties the merged scanner did not yet guarantee:

1. **Path traversal** — a scanned container controls its own filesystem, so a
   crafted ``find`` result like ``/workspace/../../etc/passwd`` must NOT let a
   write escape the scan tempdir onto the coding-security pod. Such a file is
   skipped and the fetch flagged incomplete.
2. **Partial-download honesty** — a dropped download chunk (or a failed
   ``find``) means the scan examined fewer files than the repo holds; the fetch
   reports ``incomplete=True`` so the caller degrades the grade instead of
   trusting a scan of an unknown-incomplete file set.
3. **Configurable budgets** — the scan / fetch wall-clock budgets come from
   settings (env-tunable), not hardcoded module constants.
"""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.container_models import ContainerInfo, ContainerStatus
from routers.security import container_scan


def _remote_container(tmp_path):
    """A ContainerInfo whose codebase_path is NOT a local dir → triggers fetch."""
    return ContainerInfo(
        container_name="victim",
        api_endpoint="http://localhost:8080",
        codebase_path="/workspace",  # not a real local dir on the test host
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        # ``ServiceClient._request`` treats a falsy ``.content`` as "no body"
        # and returns None without parsing, so the stub must look non-empty.
        self.content = b"{}"
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def _fake_client(find_stdout, read_map, *, find_status=200, read_status=200, read_statuses=None):
    """Build a fake httpx.AsyncClient yielding a find result then a bulk read.

    The production code now reaches coding-containers through
    ``CodingWorkspacesClient``, which drives ``httpx.AsyncClient.request(...)``
    and closes the client itself rather than using ``async with``. The stub
    therefore speaks both shapes: ``request``/``aclose``/``is_closed`` for the
    SDK, and the original ``post``/``__aenter__`` for any direct httpx caller.

    ``read_statuses`` makes the read endpoint fail a given number of times
    before succeeding: each read consumes the next status, and the last one
    repeats. ``client.read_calls`` counts read attempts.
    """
    statuses = list(read_statuses or [])

    class _FakeAsyncClient:
        is_closed = False
        read_calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aclose(self):
            return None

        async def request(self, _method, url, **kwargs):
            return await self.post(url, **kwargs)

        async def post(self, _url, **kwargs):
            cmd = kwargs["json"]["command"]
            if cmd[0] == "find":
                return _FakeResp({"stdout": find_stdout}, status_code=find_status)
            # python bulk reader: argv[4:] are the requested paths
            self.read_calls += 1
            if len(statuses) > 1:
                status = statuses.pop(0)
            else:
                status = statuses[0] if statuses else read_status
            return _FakeResp({"stdout": json.dumps(read_map)}, status_code=status)

    return _FakeAsyncClient()


@pytest.mark.asyncio
async def test_local_codebase_short_circuits(tmp_path):
    """An already-local codebase → no fetch, temp_dir None, not incomplete."""
    ci = ContainerInfo(
        container_name="local",
        api_endpoint="http://localhost:8080",
        codebase_path=str(tmp_path),  # a real dir
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )
    result = await container_scan._materialize_codebase(ci, "local", "tenant-1")
    assert result.temp_dir is None
    assert result.incomplete is False


@pytest.mark.asyncio
async def test_clean_fetch_is_complete(tmp_path):
    """A full fetch materialises files and reports incomplete=False."""
    ci = _remote_container(tmp_path)
    client = _fake_client(
        "/workspace/src/app.py\n/workspace/util.py\n",
        {"/workspace/src/app.py": "import os", "/workspace/util.py": "x = 1"},
    )
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is False
        assert result.temp_dir is not None
        # Both files landed under the tempdir.
        assert os.path.isfile(os.path.join(result.temp_dir, "src", "app.py"))
        assert os.path.isfile(os.path.join(result.temp_dir, "util.py"))
    finally:
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_skipped_dotenv_flags_incomplete(tmp_path):
    """A silently skipped .env is a secrets-coverage gap → degraded fetch.

    The bulk reader omits a file it cannot read or that exceeds the per-file
    cap WITHOUT an error; for a dotenv file that means the secret engines never
    examined it, so the fetch must not read as clean.
    """
    ci = _remote_container(tmp_path)
    client = _fake_client(
        "/workspace/.env\n/workspace/app.py\n",
        {"/workspace/app.py": "x = 1"},  # .env omitted, as the real reader does
    )
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is True
        assert os.path.isfile(os.path.join(result.temp_dir, "app.py"))
        assert not os.path.exists(os.path.join(result.temp_dir, ".env"))
    finally:
        import shutil

        shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_skipped_non_dotenv_source_is_the_documented_bound(tmp_path):
    """A skipped ordinary source file is the deliberate per-file cap.

    It is a coverage bound, not a secret-scan gap, so it must NOT mark the
    fetch incomplete (the documented behaviour the dotenv rule leaves alone).
    """
    ci = _remote_container(tmp_path)
    client = _fake_client("/workspace/app.py\n", {})  # app.py over the cap
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is False
        assert not os.path.exists(os.path.join(result.temp_dir, "app.py"))
    finally:
        import shutil

        shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_path_traversal_is_skipped_and_flags_incomplete(tmp_path):
    """A ../-escaping path must NOT be written outside the tempdir; fetch flagged.

    Hermetic: the scan tempdir is pinned UNDER pytest's ``tmp_path`` and the
    escape target is a sibling under ``tmp_path`` (auto-cleaned), so the test
    never touches the real /tmp and cannot be polluted by a prior run.
    """
    ci = _remote_container(tmp_path)
    scan_dir = tmp_path / "scan-victim"
    scan_dir.mkdir()
    escape_target = tmp_path / "evil.py"  # one level above scan_dir → escapes it
    # The container returns a benign file AND a traversal payload pointing just
    # outside the scan tempdir.
    client = _fake_client(
        "/workspace/ok.py\n/workspace/../evil.py\n",
        {
            "/workspace/ok.py": "import os",
            "/workspace/../evil.py": "OWNED = True",
        },
    )
    with (
        patch("httpx.AsyncClient", return_value=client),
        patch(
            "services.scan_runner.tempfile.mkdtemp",
            return_value=str(scan_dir),
        ),
    ):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    # Benign file materialised; traversal file skipped, fetch degraded.
    assert result.incomplete is True
    assert result.temp_dir == str(scan_dir)
    assert os.path.isfile(os.path.join(result.temp_dir, "ok.py"))
    # The escaping write never happened (would have landed at tmp_path/evil.py).
    assert not escape_target.exists()
    # Nothing escaped the tempdir root.
    root = os.path.realpath(result.temp_dir)
    for dirpath, _dirs, names in os.walk(result.temp_dir):
        for name in names:
            p = os.path.realpath(os.path.join(dirpath, name))
            assert os.path.commonpath([p, root]) == root


@pytest.mark.asyncio
async def test_dropped_chunk_flags_incomplete(tmp_path):
    """A chunk that fails every attempt means partial coverage → incomplete."""
    ci = _remote_container(tmp_path)
    client = _fake_client(
        "/workspace/a.py\n",
        {},  # ignored — read returns non-200
        read_status=503,
    )
    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is True
        # The fetch tried the chunk three times before giving up.
        assert client.read_calls == 3
    finally:
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_transient_chunk_failure_is_retried(tmp_path):
    """A chunk that fails once then succeeds is a COMPLETE fetch, no degrade."""
    ci = _remote_container(tmp_path)
    client = _fake_client(
        "/workspace/a.py\n",
        {"/workspace/a.py": "x = 1"},
        read_statuses=[503, 200],
    )
    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is False
        assert client.read_calls == 2
        assert os.path.isfile(os.path.join(result.temp_dir, "a.py"))
    finally:
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_find_failure_flags_incomplete(tmp_path):
    """A failed find (no file list at all) → incomplete=True, empty tempdir."""
    ci = _remote_container(tmp_path)
    client = _fake_client("", {}, find_status=500)
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is True
    finally:
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_scan_budget_reads_from_settings(monkeypatch):
    """_run_scan_bounded uses the settings budget, not a hardcoded constant.

    Uses a real SecurityScanService so the timeout path runs its real
    ``build_partial_result``: with nothing accumulated (the scan hangs before any
    finding) it yields an honest degraded grade F — never a fake pass.
    """
    from config import settings as settings_mod
    from services.security_scan_service import SecurityScanService

    settings_mod.get_settings.cache_clear()
    monkeypatch.setenv("SECURITY_SCAN_BUDGET_SECONDS", "0.01")

    async def _never_returns(*_a, **_k):
        import asyncio

        await asyncio.sleep(5)

    svc = SecurityScanService()
    monkeypatch.setattr(svc, "scan_container", _never_returns)
    ci = _remote_container(None)
    req = MagicMock()

    result = await container_scan._run_scan_bounded(svc, ci, req, "victim")
    # Budget of 0.01s → timeout path → honest degraded grade F (empty partial).
    assert result.security_grade == "F"
    assert result.scan_degraded is True
    assert result.total_vulnerabilities == 0
    assert result.scan_duration_seconds == pytest.approx(0.01)
    settings_mod.get_settings.cache_clear()


def _capped_client(find_stdout, read_map, *, max_paths, oversized=()):
    """Fake coding-containers that clips /exec stdout like the real 1 MiB cap.

    A read request naming more than ``max_paths`` files, or naming any path in
    ``oversized``, comes back ``truncated: True`` with a cut-off (invalid JSON)
    stdout — exactly what openplanner's 2.4 MB 400-file chunk produced.
    """
    calls = []

    class _CappedAsyncClient:
        is_closed = False

        async def aclose(self):
            return None

        async def request(self, _method, _url, **kwargs):
            cmd = kwargs["json"]["command"]
            if cmd[0] == "find":
                return _FakeResp({"stdout": find_stdout})
            paths = cmd[4:]
            calls.append(paths)
            if len(paths) > max_paths or any(p in oversized for p in paths):
                return _FakeResp({"stdout": '{"/workspace/a.py": "imp', "truncated": True})
            return _FakeResp({"stdout": json.dumps({p: read_map[p] for p in paths})})

    return _CappedAsyncClient(), calls


@pytest.mark.asyncio
async def test_truncated_chunk_is_split_until_it_fits(tmp_path):
    """A clipped chunk is bisected and re-read; every file lands, fetch complete."""
    ci = _remote_container(tmp_path)
    names = [f"/workspace/m{i}.py" for i in range(7)]
    client, calls = _capped_client(
        "\n".join(names) + "\n", {n: f"x = {i}" for i, n in enumerate(names)}, max_paths=2
    )
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is False
        for i in range(7):
            assert os.path.isfile(os.path.join(result.temp_dir, f"m{i}.py"))
        # The full chunk was tried first (and clipped), then re-read in halves.
        assert calls[0] == names
        assert len(calls) > 1
    finally:
        import shutil

        shutil.rmtree(result.temp_dir, ignore_errors=True)


def _flaky_read_client(find_stdout, read_map, failure):
    """Fake client: a read of more than two files returns *failure()* once."""

    class _FlakyAsyncClient:
        is_closed = False
        read_calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aclose(self):
            return None

        async def request(self, _method, url, **kwargs):
            return await self.post(url, **kwargs)

        async def post(self, _url, **kwargs):
            cmd = kwargs["json"]["command"]
            if cmd[0] == "find":
                return _FakeResp({"stdout": find_stdout})
            paths = cmd[4:]
            self.read_calls += 1
            if len(paths) > 2 and self.read_calls == 1:
                return failure()
            return _FakeResp({"stdout": json.dumps({p: read_map[p] for p in paths})})

    return _FlakyAsyncClient()


class _EmptyBodyResp(_FakeResp):
    """A response with no body — the SDK returns ``None`` instead of parsing it."""

    def __init__(self):
        super().__init__({})
        self.content = b""
        self.text = ""


@pytest.mark.asyncio
async def test_unparseable_chunk_is_split_and_recovered(tmp_path):
    """An unparseable chunk is a lost response, not a coverage gap: bisect it.

    A silent ``incomplete = True`` here lost ~170 of 1052 files on the
    openplanner branch scan with no log line; the smaller chunks succeed.
    """
    ci = _remote_container(tmp_path)
    names = [f"/workspace/f{i}.py" for i in range(4)]
    client = _flaky_read_client(
        "\n".join(names) + "\n",
        {n: f"x = {i}" for i, n in enumerate(names)},
        lambda: _FakeResp({"stdout": "this is not the reader's json"}),
    )
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is False
        for i in range(4):
            assert os.path.isfile(os.path.join(result.temp_dir, f"f{i}.py"))
        assert client.read_calls > 1
    finally:
        import shutil

        shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_empty_chunk_body_is_split_and_recovered(tmp_path):
    """An empty /exec body is re-read in halves, not believed lost."""
    ci = _remote_container(tmp_path)
    names = [f"/workspace/g{i}.py" for i in range(4)]
    client = _flaky_read_client(
        "\n".join(names) + "\n",
        {n: f"y = {i}" for i, n in enumerate(names)},
        _EmptyBodyResp,
    )
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is False
        for i in range(4):
            assert os.path.isfile(os.path.join(result.temp_dir, f"g{i}.py"))
        assert client.read_calls > 1
    finally:
        import shutil

        shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_single_file_over_cap_flags_incomplete(tmp_path):
    """A lone file whose output alone exceeds the cap is skipped and flagged."""
    ci = _remote_container(tmp_path)
    client, _calls = _capped_client(
        "/workspace/ok.py\n/workspace/huge.py\n",
        {"/workspace/ok.py": "x = 1", "/workspace/huge.py": "y" * 10},
        max_paths=10,
        oversized={"/workspace/huge.py"},
    )
    with patch("httpx.AsyncClient", return_value=client):
        result = await container_scan._materialize_codebase(ci, "victim", "tenant-1")
    try:
        assert result.incomplete is True
        assert os.path.isfile(os.path.join(result.temp_dir, "ok.py"))
        assert not os.path.exists(os.path.join(result.temp_dir, "huge.py"))
    finally:
        import shutil

        shutil.rmtree(result.temp_dir, ignore_errors=True)
