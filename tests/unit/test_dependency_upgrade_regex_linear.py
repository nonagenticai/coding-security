"""Regression: two dependency_upgrade regexes were super-linear (ReDoS).

Measured 2026-10-12: the Cargo.toml constraint regex ``^\\s*name\\s*=...``
(MULTILINE; ``\\s*`` spans newlines, so every line start rescanned the rest)
took >68 s on 200k whitespace, and the repo-url regex
``.*github\\.com[/:]([^/]+)/([^/.]+)`` did not finish in 120 s on 200k of
``github.com:``. The same shape was in the PEP 508 extras strip ``\\[.*?\\]``
(20k ``[`` -> 0.87 s, quadratic) and the ``uv tree --outdated`` line regex
(``a v`` + 20k ``x`` -> 0.87 s); both are covered here too. Each timing runs
in a child process with a hard timeout so a regression fails the test instead
of hanging the suite.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from services.dependency_upgrade import _find_constraint, _github_owner_repo

SRC = str(Path(__file__).resolve().parents[2] / "src")
N = 200_000
BUDGET_S = 0.5

_CHILD = """
import sys, time
sys.path.insert(0, {src!r})
from services.dependency_upgrade import _find_constraint, _github_owner_repo
from services.dependency_extraction import DependencyExtractor
from services.dependency_graph import DependencyGraphBuilder
from services.workspace_latest_versions import parse_uv_tree_outdated
N = {n}
inputs = {{
    "cargo_ws": lambda: _find_constraint("serde", {{"Cargo.toml": " " * N}}),
    "cargo_ws_nl": lambda: _find_constraint("serde", {{"Cargo.toml": " \\n" * (N // 2)}}),
    "cargo_name_ws": lambda: _find_constraint("serde", {{"Cargo.toml": "serde " * (N // 6)}}),
    "gh_colon": lambda: _github_owner_repo("github.com:" * (N // 11)),
    "gh_colon_tail": lambda: _github_owner_repo("github.com:" + "a" * N),
    "gh_slash_tail": lambda: _github_owner_repo("github.com/" + "a" * N),
    "extras_open": lambda: DependencyExtractor().parse_pypi_parts("[" * N),
    "graph_extras_open": lambda: DependencyGraphBuilder()._parse_pypi_requirement("[" * N),
    "uv_tree_no_latest": lambda: parse_uv_tree_outdated("a v" + "x" * N),
}}
fn = inputs[sys.argv[1]]
t = time.process_time()
fn()
print(time.process_time() - t)
"""


@pytest.mark.parametrize(
    "case",
    [
        "cargo_ws",
        "cargo_ws_nl",
        "cargo_name_ws",
        "gh_colon",
        "gh_colon_tail",
        "gh_slash_tail",
        "extras_open",
        "graph_extras_open",
        "uv_tree_no_latest",
    ],
)
def test_adversarial_input_is_linear(case):
    try:
        out = subprocess.run(
            [sys.executable, "-c", _CHILD.format(src=SRC, n=N), case],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{case}: did not finish in 10 s (super-linear regex)")
    assert float(out.stdout.strip()) < BUDGET_S


def _old_github(url: str) -> tuple[str, str] | None:
    m = re.match(r".*github\.com[/:]([^/]+)/([^/.]+)", url)
    return (m.group(1), m.group(2)) if m else None


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/acme/widgets.git",
        "git@github.com:acme/widgets.git",
        "https://github.com/acme/widgets",
        "https://github.com/acme/widgets/tree/main",
        "https://mirror/github.com/a/b/github.com/c/d",
        "https://gitlab.com/acme/widgets",
        "github.com/acme",
        "",
    ],
)
def test_github_owner_repo_matches_the_old_regex(url):
    assert _github_owner_repo(url) == _old_github(url)


def test_cargo_constraint_still_found():
    cargo = '[dependencies]\n  serde = "1.0"\ntokio = "1.38"\n'
    assert _find_constraint("serde", {"Cargo.toml": cargo}) == "1.0"
    assert _find_constraint("tokio", {"Cargo.toml": cargo}) == "1.38"
    assert _find_constraint("rand", {"Cargo.toml": cargo}) is None
