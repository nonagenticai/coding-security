ARG BASE_REGISTRY=docker.io

# --- Stage 1: Builder ---
FROM ${BASE_REGISTRY}/library/python:3.14-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./

# git is required because coding-client is a pinned GIT dependency (a public repository, not a
# package on an index). uv shells out to the git CLI for those; the slim base does not ship it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN uv sync --frozen --no-dev --no-install-project

# --- Stage 2: Production ---
FROM ${BASE_REGISTRY}/library/python:3.14-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /bin/

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Trivy (image CVEs via trivy_scanner + IaC/misconfig via iac_scanner's
# `trivy config`). Pinned to a REAL release: v0.58.2 never existed (the GitHub
# asset 404s), so the previous `|| true` silently shipped a trivy-LESS image for
# BOTH scanners (the image-CVE path was masked by the grype fallback). trivy is
# load-bearing, so this retries on transient flakes and then VERIFIES the binary
# — a bad pin or a failed download now fails the build LOUDLY instead of
# degrading the security scanner in silence.
RUN for i in 1 2 3; do \
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin v0.76.2 && break || sleep 5; \
    done && trivy --version

# Warm the trivy misconfig (`trivy config`) checks bundle into the image at a
# fixed, world-accessible cache dir. The first `trivy config` on a freshly
# rolled pod otherwise downloads the OPA checks bundle on demand, adding tens of
# seconds to the IaC container scan (E3.15 latency blocker). TRIVY_CACHE_DIR is
# honoured by trivy at both build (warm) and runtime, so iac_scanner needs no
# change. Best-effort (|| true): if the warm download flakes, runtime falls back
# to a cold download (prior behaviour) — it is an optimisation, not load-bearing.
# Mode 0777 so the runtime `appuser` can read the bundle and refresh it if stale.
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
RUN mkdir -p /opt/trivy-cache /tmp/trivy-warm \
    && printf 'FROM scratch\nUSER root\n' > /tmp/trivy-warm/Dockerfile \
    && trivy config --cache-dir /opt/trivy-cache --quiet /tmp/trivy-warm || true; \
    chmod -R 0777 /opt/trivy-cache && rm -rf /tmp/trivy-warm

# Bake the VULNERABILITY database (`trivy image --download-db-only`) next to the
# misconfig bundle. This is the data source for the base-image OS-CVE engine
# (trivy_image_scanner): the runtime pod has no egress to the DB publisher, and
# a missing DB must fail the scan loudly rather than report a clean image.
# LOAD-BEARING, so the same retry + VERIFY pattern as the semgrep/OSV bakes —
# NOT `|| true`. The verify pins CONTENT, not shape:
#   * the file exists and is at least 500 MB (the real DB is ~1.6 GB; a stub or
#     a truncated download is caught here),
#   * its metadata parses as a version-2 DB with a build timestamp,
#   * a known, long-lived record (the zlib advisory CVE-2023-45853, carried by
#     Debian/Ubuntu/Alpine) is present in the DB bytes. If the upstream feed
#     loses it the build fails loudly instead of shipping an empty DB — the same
#     "pin the content, not the shape" rule that the semgrep bake records.
# Cost, measured 2026-11-05: 132 MiB compressed download / 1.6 GiB on disk.
# The weekly Monday rebuild (ci-cd.yaml schedule) refreshes it, exactly like the
# OSV DB; the deployment's seed-trivy-cache init container copies
# /opt/trivy-cache into the emptyDir TRIVY_CACHE_DIR, so scans use it with
# --skip-db-update and never touch the network.
RUN set -e; \
    ok=0; \
    for i in 1 2 3; do \
      if trivy image --download-db-only --cache-dir /opt/trivy-cache; then ok=1; break; fi; \
      echo "trivy DB download attempt ${i} failed; retrying" >&2; \
      sleep 5; \
    done; \
    [ "$ok" = "1" ] || { echo "FATAL: trivy vulnerability DB download failed after 3 attempts" >&2; exit 1; }; \
    python3 -c "import json, os; \
p = '/opt/trivy-cache/db/trivy.db'; size = os.path.getsize(p); \
assert size > 500 * 1024 * 1024, f'trivy DB is only {size} bytes — truncated download'; \
m = json.load(open('/opt/trivy-cache/db/metadata.json')); \
assert m.get('Version') == 2, m; \
assert m.get('UpdatedAt'), m; \
print('trivy DB OK:', m['UpdatedAt'], f'{size} bytes')"; \
    grep -aq 'CVE-2023-45853' /opt/trivy-cache/db/trivy.db || { \
      echo "FATAL: baked trivy DB has no known zlib advisory (CVE-2023-45853) — wrong or empty DB" >&2; exit 1; }; \
    chmod -R a+rX /opt/trivy-cache

# Install Grype (image CVEs via grype_scanner). Load-bearing — grype is the
# engine that masked trivy's silent absence in E3.9, so it must never itself
# vanish unnoticed. Same treatment as trivy above: retry on transient flakes,
# then VERIFY the binary (dropped the old `|| true` that swallowed a failed
# download and shipped a grype-less image with no signal).
RUN for i in 1 2 3; do \
      curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin v0.121.2 && break || sleep 5; \
    done && grype version

# Install Syft (SBOM via syft_scanner). Same retry + verify rationale as grype.
RUN for i in 1 2 3; do \
      curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin v1.57.0 && break || sleep 5; \
    done && syft version

# Install semgrep (multi-language SAST) as an ISOLATED CLI. semgrep pins
# rich<13.6, irreconcilable with the app venv (rich>=13.9.4 via coding-client ->
# pydantic-ai -> fastmcp-slim), and the scanner only shells out to the `semgrep`
# CLI — so it lives in its own uv-tool venv (world-readable under /opt/uv) with
# the shim on PATH in /usr/local/bin, exactly like the Trivy/Grype/Syft binaries
# above. Pinned to a managed 3.12 (semgrep does not yet target 3.14).
ENV UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_TOOL_DIR=/opt/uv/tools \
    UV_PYTHON_INSTALL_DIR=/opt/uv/python
RUN uv tool install --python 3.12 'semgrep>=1.95' && chmod -R a+rX /opt/uv || true

# Bake the semgrep community ruleset OFFLINE. `--config auto` is UNUSABLE in the
# runtime pod: it fetches the registry ruleset at scan time, which is (1) gated
# behind metrics — with `--metrics=off` semgrep hard-errors "Cannot create auto
# config when metrics are off" — and (2) unreachable regardless, because egress
# to the semgrep registry is blocked by the ambient-mesh policy BY DESIGN (same
# as api.osv.dev below). So every multi-language SAST run was silently degraded
# (0 semgrep findings, augmentation_degraded=true) on EVERY scan. Fix: mirror the
# OSV offline-DB pattern — materialize the curated `p/security-audit` registry
# pack at build time (CI has egress; the pack URL returns the same concrete rules
# `--config auto` would fetch, as one file) into a world-readable dir the scanner
# points --config at, then VERIFY offline that the rules LOAD and match a known
# finding (fail the build LOUDLY, never ship a 0-rule image). `security-audit`
# (~225 multi-language SAST rules) loads in seconds; the whole semgrep-rules repo
# (~2k rules) is too slow to parse per scan. The image is the refresh vehicle —
# a scheduled rebuild re-pulls the current pack.
#
# ⚠️ 2026-08-15: the registry endpoint switched from a YAML rendering to JSON and
# broke EVERY build of this image (6 buildx attempts, ~7m of retries, then a hard
# fail). The pack itself was fine — 200, 433 KB, 225 rules — so the outage was
# entirely in the validation, which asserted the YAML SYNTAX
# (`startswith('rules:')` and `count('- id:') > 50`) rather than the content.
# The check below parses instead: JSON when the body starts with `{`, the legacy
# YAML string-check otherwise, so it accepts either rendering and still enforces
# >50 rules (the registry served YAML again on 2026-10-29). The app reads the pack
# with yaml.safe_load, which takes both; the final stage asserts the app's reader
# finds the pack's languages. The `.yaml` filename is kept deliberately — YAML is a superset of
# JSON, so semgrep loads it either way, and the smoke test below is the real
# functional proof that it did.
#
# The lesson worth keeping: a guard that pins the SHAPE of an upstream response
# fails on a cosmetic change while a guard that pins its CONTENT does not. The
# smoke assertion (>=1 finding on a blatant `shell=True`/`eval`) is the one that
# actually proves the bake works; it never fired, because the syntax check
# rejected a perfectly good pack first.
ENV SEMGREP_RULESET=/opt/semgrep-rules
RUN set -e; \
    mkdir -p "${SEMGREP_RULESET}"; \
    for i in 1 2 3; do \
      curl -sfL "https://semgrep.dev/c/p/security-audit" \
        -o "${SEMGREP_RULESET}/security-audit.yaml" && break || sleep 5; \
    done; \
    chmod -R a+rX "${SEMGREP_RULESET}"; \
    python3 -c "import sys,json; t=open('${SEMGREP_RULESET}/security-audit.yaml').read().lstrip(); \
ok=(len(json.loads(t).get('rules',[]))>50) if t.startswith('{') else (t.startswith('rules:') and t.count('- id:')>50); \
sys.exit(0 if ok else 1)"; \
    printf 'import subprocess\nsubprocess.call(cmd, shell=True)\neval(userinput)\n' > /tmp/semgrep-smoke.py; \
    semgrep scan --config "${SEMGREP_RULESET}" --json --metrics=off --disable-version-check --quiet \
      /tmp/semgrep-smoke.py > /tmp/semgrep-smoke.json 2>/tmp/semgrep-smoke.err || true; \
    ! grep -qi 'auto config' /tmp/semgrep-smoke.err; \
    python3 -c "import json; d=json.load(open('/tmp/semgrep-smoke.json')); r=d.get('results'); assert isinstance(r,list) and len(r)>=1, 'vendored semgrep rules loaded 0 findings on a blatant shell=True/eval smoke — bake is broken'; print('semgrep offline OK: smoke findings=', len(r))"; \
    rm -f /tmp/semgrep-smoke.py /tmp/semgrep-smoke.json /tmp/semgrep-smoke.err

# Bake the OSV offline dependency-CVE database (PyPI + crates.io + npm). The runtime pod's egress
# to api.osv.dev is blocked by the ambient-mesh policy BY DESIGN, and the pod
# CANNOT lazily re-download — so this DB is LOAD-BEARING. Unlike a trivy
# cache-warm (|| true), a missing DB would make the scanner silently report 0
# CVEs and the development_security_patch delta gate could never see a baseline
# HIGH. So we mirror the trivy/grype *binary install* pattern (retry + VERIFY,
# NOT `|| true`): fetch the flat all.zip, re-index into one file per package,
# then assert a known record exists — fail the build LOUDLY otherwise. The
# build runs on a CI runner WITH egress; only the runtime pod is blocked.
# The image is the refresh vehicle — a scheduled rebuild re-pulls all.zip.
ENV OSV_OFFLINE_DB_DIR=/opt/osv-db
COPY scripts/build_osv_offline_db.py /tmp/build_osv_offline_db.py
#
# Ecosystems baked: PyPI (Python sources), crates.io (Rust targets: Cargo.lock
# deps resolve here) and npm (package-lock.json / yarn.lock, including the
# nested lockfiles the extractor now reads at any depth — without it every npm
# package came back UNCHECKED, never clean).
# crates.io measured 2026-10-27: 1850 crates / 2995 records, +74.9 MiB on disk,
# +4.9 MiB gzipped layer.
# npm measured 2026-11-04: 226,432 packages / 231,202 records from a 210 MiB
# all.zip, +924 MiB on disk / ~21 s to index. It is the largest baked ecosystem
# by far; that disk cost buys real npm CVE coverage (openplanner alone: 164 npm
# packages that previously could only be reported as unchecked).
# The asserts pin CONTENT (a known record per ecosystem and a package floor),
# not the shape of the upstream zip.
RUN set -e; \
    for eco in PyPI crates.io npm; do \
      for i in 1 2 3; do \
        curl -sfL "https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip" \
          -o "/tmp/osv-${eco}.zip" && break || sleep 5; \
      done; \
      python3 /tmp/build_osv_offline_db.py "/tmp/osv-${eco}.zip" "${OSV_OFFLINE_DB_DIR}" --ecosystem "${eco}"; \
      rm -f "/tmp/osv-${eco}.zip"; \
    done; \
    rm -f /tmp/build_osv_offline_db.py; \
    chmod -R a+rX "${OSV_OFFLINE_DB_DIR}"; \
    test -s "${OSV_OFFLINE_DB_DIR}/PyPI/python-jose.json"; \
    grep -q RUSTSEC-2021-0003 "${OSV_OFFLINE_DB_DIR}/crates.io/smallvec.json"; \
    test -s "${OSV_OFFLINE_DB_DIR}/npm/lodash.json"; \
    grep -q GHSA-xvch-5gv4-984h "${OSV_OFFLINE_DB_DIR}/npm/minimist.json"; \
    test -s "${OSV_OFFLINE_DB_DIR}/manifest.json"; \
    python3 -c "import json, os; from datetime import datetime; \
m = json.load(open(os.environ['OSV_OFFLINE_DB_DIR'] + '/manifest.json')); \
assert m['schema_version'] == 1, m; \
datetime.fromisoformat(m['generated_at'].replace('Z', '+00:00')); \
assert m['ecosystems']['PyPI']['packages'] > 1000, m; \
assert m['ecosystems']['crates.io']['packages'] > 500, m; \
assert m['ecosystems']['npm']['packages'] > 100000, m; \
print('osv manifest OK:', m['generated_at'], {e: v['packages'] for e, v in m['ecosystems'].items()}, 'packages')"

# Create appuser BEFORE the copies so each COPY can set ownership inline via
# --chown. A trailing `chown -R appuser:appuser /app` instead costs ~14 min on
# an ARC runner AND rewrites every file into a second, duplicate image layer —
# together with the resulting slow push that blew the 30 min build cap (jobs are
# reported as `cancelled`, not `failure`). /app itself is chowned non-recursively
# so the directory keeps the ownership the old recursive chown gave it.
RUN useradd -m -u 1000 appuser && mkdir -p /app && chown appuser:appuser /app
WORKDIR /app
COPY --from=builder --chown=appuser:appuser /app/uv.lock /app/uv.lock
COPY --from=builder --chown=appuser:appuser /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --chown=appuser:appuser src/ ./src/

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"
USER appuser

# Real-DB proof of the per-version advisory path (the unit tests have no baked DB):
# smallvec 0.6.13, 0.6.14 and 1.6.0 resolved together: RUSTSEC-2021-0003 (>=0.6.3
# <0.6.14, >=1.0.0 <1.6.1) lands on 0.6.13 AND 1.6.0, never on 0.6.14,
# both in the dependency scan (scanner + attach_vulnerabilities) and in the
# per-repo dependency list (_attach_advisories).
RUN python -c "import asyncio; \
from models.package_manager_models import ExternalPackage; \
from models.dependency_inventory_models import DependencyEntry, EcosystemDependencies; \
from services.dependency_visualization import DependencyVulnerabilityScanner; \
from services.dependency_analyzer import attach_vulnerabilities; \
from routers.security.dependency_inventory import _attach_advisories; \
vs = ('0.6.13', '0.6.14', '1.6.0'); \
pk = [ExternalPackage(name='smallvec', version=v, ecosystem='crates.io') for v in vs]; \
s = DependencyVulnerabilityScanner(); asyncio.run(s.scan_vulnerabilities(pk)); \
scan = {p.version: {v.id for v in p.vulnerabilities or []} for p in attach_vulnerabilities(pk, s.package_vulnerabilities)}; \
eco = EcosystemDependencies(ecosystem='crates.io', resolved=[DependencyEntry(name='smallvec', version=v, direct=True, source_file='Cargo.lock') for v in vs]); \
errors = asyncio.run(_attach_advisories(eco, '/opt/osv-db')); \
inv = {e.version: set(e.advisories) for e in eco.resolved if e.advisories_checked}; \
assert not s.lookup_errors and not errors, (s.lookup_errors, errors); \
assert all([v for v in vs if 'RUSTSEC-2021-0003' in r[v]] == ['0.6.13', '1.6.0'] for r in (scan, inv)), (scan, inv); \
print('osv per-version OK', scan, inv)"
# GET /api/security/patterns derives semgrep's languages from the baked pack: the
# app's own reader must find them, whatever rendering (JSON / YAML) was baked.
RUN python -c "from routers.security.vulnerabilities import _semgrep_pack_languages as f; \
langs = f('/opt/semgrep-rules'); assert {'python', 'javascript'} <= langs, langs; \
print('semgrep pack languages OK', sorted(langs))"

# 8693 = application API. 9693 = dedicated Prometheus metrics listener, started
# by the app's lifespan (src/metrics_server.py) and serving ONLY /metrics, so the
# scrape grant can be port-scoped away from the API surface.
EXPOSE 8693 9693

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8693/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8693"]
