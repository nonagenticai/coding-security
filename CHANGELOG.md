# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `requires-python` is bounded to `>=3.14,<3.15`. With an open upper bound, `uv` had to resolve a
  second split for `python_full_version >= '3.15'`, and no solution exists there — which is what
  made Dependabot's update job fail on `main` with `dependency_file_not_resolvable` against
  `fastmcp`, `mcp` and `packaging`. Nothing about those three packages was wrong. `uv.lock` is
  regenerated for the narrower range, so it no longer carries Python 3.15 marker variants.

## [1.2.0] - 2026-11-13

First public release.
