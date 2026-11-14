"""A real, local stand-in for the two coding-containers routes the remote path uses.

``GET /api/workspaces/{name}`` answers the workspace record and
``POST /api/workspaces/{name}/exec`` RUNS the posted argv with ``subprocess`` in a
tmp dir laid out like ``/workspace`` (the service is pointed at it with
``WORKSPACE_ROOT``), with coding-containers' response shape: ``exit_code``,
``stdout``, ``stderr``, ``truncated`` / ``bytes_omitted`` past the output budget.
Nothing in the service is patched: its real SDK client talks HTTP to this server,
and the real find / cat / ``python -c`` commands run against real files.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

#: The workspace record's ``codebase_path``: never a local dir, so the service
#: takes its remote (exec) path, as it does in the cluster.
REMOTE_CODEBASE_PATH = "/nonexistent-remote-workspace"

#: The only programs this stand-in will run — exactly the ones the service under
#: test issues: ``find`` and ``cat`` for reads, ``python -c`` for the inspect
#: step. Anything else is refused rather than executed, so a regression that
#: starts shelling out to something new fails here loudly instead of running it.
ALLOWED_PROGRAMS = frozenset({"find", "cat", "python"})


class RefusedCommandError(Exception):
    """The posted ``argv[0]`` is not one this stand-in is allowed to run."""


class WorkspaceServer:
    def __init__(
        self,
        root: Path,
        name: str = "ws",
        max_output: int = 1 << 20,
        codebase_path: str = REMOTE_CODEBASE_PATH,
        clip_only: str | None = None,
    ) -> None:
        """*codebase_path*: the record's path; a local dir puts the service in local mode.
        *clip_only*: apply *max_output* only to commands with this argv[0]."""
        self.root = root
        self.clip_only = clip_only
        self.codebase_path = codebase_path
        self.name = name
        self.max_output = max_output
        self.commands: list[list[str]] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> WorkspaceServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def _exec(self, body: dict) -> dict:
        argv = list(body["command"])
        program = argv[0] if argv else ""
        if program not in ALLOWED_PROGRAMS:
            raise RefusedCommandError(
                f"refusing to run {program!r}: this stand-in only runs "
                f"{', '.join(sorted(ALLOWED_PROGRAMS))}"
            )
        self.commands.append(argv)
        if program == "python":
            argv[0] = sys.executable
        proc = subprocess.run(
            argv,
            cwd=self.root,
            capture_output=True,
            timeout=body.get("timeout") or 60,
            check=False,
        )
        out, err = proc.stdout, proc.stderr
        if self.clip_only is not None and body["command"][0] != self.clip_only:
            return {
                "exit_code": proc.returncode,
                "stdout": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace"),
                "duration": 0.0,
                "truncated": False,
                "bytes_omitted": 0,
            }
        omitted = max(len(out) - self.max_output, 0) + max(len(err) - self.max_output, 0)
        return {
            "exit_code": proc.returncode,
            "stdout": out[: self.max_output].decode("utf-8", "replace"),
            "stderr": err[: self.max_output].decode("utf-8", "replace"),
            "duration": 0.0,
            "truncated": omitted > 0,
            "bytes_omitted": omitted,
        }

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def _reply(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.rstrip("/") != f"/api/workspaces/{server.name}":
                    self._reply(404, {"detail": "not found"})
                    return
                self._reply(
                    200,
                    {
                        "container": {
                            "container_name": server.name,
                            "api_endpoint": f"http://{server.name}:8080",
                            "codebase_path": server.codebase_path,
                            "repo_url": "https://github.com/o/target",
                            "branch": "main",
                            "status": "running",
                        }
                    },
                )

            def do_POST(self) -> None:  # noqa: N802
                if self.path != f"/api/workspaces/{server.name}/exec":
                    self._reply(404, {"detail": "not found"})
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                try:
                    result = server._exec(body)
                except RefusedCommandError as exc:
                    self._reply(403, {"detail": str(exc)})
                    return
                self._reply(200, result)

        return Handler
