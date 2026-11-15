# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- OSV reference URLs are matched by parsed hostname, not substring. A reference that merely
  embedded `cve.mitre.org` or `nvd.nist.gov` in its path (`https://evil.example/nvd.nist.gov/CVE-…`)
  or as a host prefix (`https://nvd.nist.gov.evil.example/…`) was accepted as a CVE catalogue
  reference; `_is_cve_reference_url()` now compares `urlsplit(url).hostname` against the catalogue
  hosts, and a regression test covers both bypass shapes.
- `requires-python` is bounded to `>=3.14,<3.15`. With an open upper bound, `uv` had to resolve a
  second split for `python_full_version >= '3.15'`, and no solution exists there — which is what
  made Dependabot's update job fail on `main` with `dependency_file_not_resolvable` against
  `fastmcp`, `mcp` and `packaging`. Nothing about those three packages was wrong. `uv.lock` is
  regenerated for the narrower range, so it no longer carries Python 3.15 marker variants.

## [1.2.0] - 2026-11-13

First public release.
