# coding-security

[![CI](https://github.com/nonagenticai/coding-security/actions/workflows/ci.yml/badge.svg)](https://github.com/nonagenticai/coding-security/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nonagenticai/coding-security)](https://github.com/nonagenticai/coding-security/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Static security analysis service for the Code Graph Helper platform. Scans source code for security vulnerabilities, analyzes project dependencies for known CVEs, detects missing system-level dependencies, and generates sandbox configurations for safe code execution.

This service is part of the `code_graph_helper` microservices suite and operates on "containers" -- named codebases managed by the `coding-containers` service.

| | |
|---|---|
| **Runtime** | Python 3.14, FastAPI + Uvicorn |
| **Depends on** | `coding-containers`, Redis, and the baked offline OSV database |
| **Runs on** | Kubernetes (container), listening on port 8693 |

## Authentication

Istio ext_authz validates license tokens on incoming requests. The `coding-client` library provides `AuthMiddleware`, which reads Istio-injected headers (enabled when `ENABLE_AUTH=true`). Tenant identity comes from the `X-Tenant-Id` header (or a `tenant_id` query parameter) set by the ext_authz filter after license validation. There is no unconditional `n8n-dev` fallback: `coding_client.auth.tenant` falls back to `DEFAULT_TENANT_ID` only for requests from trusted networks (loopback/RFC1918), and otherwise returns 401. `DEFAULT_TENANT_ID` itself has no default — when unset, credential-less fallback is refused. No direct Keycloak or JWT validation occurs in this service.

## Architecture

```
coding-security (FastAPI, port 8693)
  |
  +-- /api/security/*          -- Code vulnerability scanning + sandbox configs
  +-- /api/dependencies/*      -- Package dependency analysis (CVEs, outdated, risk)
  +-- /api/dependencies/system/* -- System-level dependency detection + script generation
  |
  +-- coding-containers:8691   -- HTTP calls to resolve container metadata
  +-- Redis                    -- Validation cache + durable async-scan queue (required in production)
  +-- /opt/osv-db (baked)      -- Offline OSV database (PyPI, crates.io, npm); see below
```

**Key services:**

| Service class | Responsibility |
|---|---|
| `SystemSecurityService` | Regex + AST-based code validation, sandbox config generation, result caching via Redis |
| `SecurityDetector` | Advanced multi-language vulnerability pattern matching (SQL injection, XSS, command injection, crypto, memory safety, etc.) |
| `SecurityScanService` | Container-scoped scanning orchestrator -- resolves files, runs detector, builds reports with grades |
| `ArchitectureDependencyAnalyzer` | Extracts dependencies from manifest files, queries OSV.dev for CVEs, builds risk reports |
| `SystemDependencyManager` | Detects OS-level dependencies (apt/yum/brew/etc.), generates install scripts, Dockerfile snippets, CI configs |
| `ContainerMetadataRegistry` | HTTP client to `coding-containers` for resolving container names to codebase paths |

## API Routes

All routes require tenant identification via the `X-Tenant-Id` header (or a `tenant_id` query parameter). Credential-less callers from trusted networks fall back to `DEFAULT_TENANT_ID` only when that variable is configured; otherwise the request is rejected with 401.

### Health / Root

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check -- returns `{status, service, version}` |
| `GET` | `/` | Service info with links to docs and health |

### Security (`/api/security`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/security/validate` | Validate a code snippet for security issues. Takes `{code, language, security_level}`, returns violations, risk score (0-100), safety verdict, and sandbox config recommendation. Supports Python (regex + AST) and JavaScript (regex). |
| `GET` | `/api/security/sandbox-config/{language}/{security_level}` | Get sandbox configuration (resource limits, capabilities, entrypoint) for a language at a given security level (`low`/`medium`/`high`/`critical`). |
| `POST` | `/api/security/analyze-vulnerabilities` | Comprehensive multi-file vulnerability analysis. Accepts `container_name` or `file_paths`, detects SQL injection, XSS, command injection, hardcoded credentials, weak crypto, buffer overflows, etc. Returns results grouped by type/severity/confidence/language with CWE/OWASP mappings. |
| `GET` | `/api/security/patterns` | List all available vulnerability detection patterns with OWASP mappings, supported languages, and pattern distribution. |
| `POST` | `/api/security/scan/{container_name}` | Full security scan of a container's codebase. Returns severity distribution, risk score, security grade (A-F), per-file results. |
| `POST` | `/api/security/scan/{container_name}/quick` | Quick scan -- limits to 100 files, high/critical only, no low-confidence findings. Designed for CI/CD. |
| `GET` | `/api/security/report/{container_name}` | Generate a comprehensive security report: executive summary, severity distribution, hotspot files, top priorities, recommendations, language breakdown. |

### Dependencies (`/api/dependencies` and `/api/security/dependencies`)

Both prefixes serve the same router (dual-mount for compatibility).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/dependencies/{container_name}` | Full dependency risk report -- extracts packages from manifest files, queries OSV.dev for CVEs, calculates risk score. |
| `GET` | `/api/dependencies/{container_name}/outdated` | List packages with newer versions available. |
| `GET` | `/api/dependencies/{container_name}/vulnerable` | List packages with known security vulnerabilities. |
| `GET` | `/api/dependencies/{container_name}/report` | Alias for `GET /{container_name}` (frontend compatibility). |
| `POST` | `/api/dependencies/{container_name}/scan` | Force a fresh dependency scan (bypasses cache). |

### System Dependencies (`/api/dependencies/system`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/dependencies/system/detect` | Detect system-level dependencies required by a project. Scans `requirements.txt`, `package.json`, etc. and checks which OS packages (libxml2-dev, libpq-dev, etc.) are missing. Query params: `project_root`, `include_optional`, `fast_mode`. |
| `POST` | `/api/dependencies/system/generate-script` | Generate a shell install script for missing system dependencies using the detected package manager. |
| `POST` | `/api/dependencies/system/generate-dockerfile` | Generate a Dockerfile `RUN apt-get install` snippet for system dependencies. |
| `POST` | `/api/dependencies/system/generate-ci-config` | Generate GitHub Actions or GitLab CI config for installing system dependencies. Query param: `platform` (`github` or `gitlab`). |
| `GET` | `/api/dependencies/system/list-known` | List all known system dependencies with installation status. |

## Configuration

Settings are Pydantic fields in `src/config/settings.py`; environment variable names are the
field names and are case-insensitive. In production (`ENVIRONMENT=production`) startup fails if
`DATABASE_URL`, `REDIS_URL`, `CONTAINERS_SERVICE_URL` or `DOCKER_REGISTRY_URL` is empty.

### Core settings

| Variable | Default | Description |
|---|---|---|
| `SERVICE_NAME` | `coding-security` | Service name for logging and telemetry |
| `VERSION` | `1.0.0` | Service version reported by `/health` and the OpenAPI document (the package version is `1.2.0` in `pyproject.toml`) |
| `ENVIRONMENT` | `production` | Environment name; any other value skips the required-in-production check |
| `PORT` | `8693` | Application listening port |
| `METRICS_PORT` | `9693` | Dedicated Prometheus listener; `0` binds an ephemeral port (tests) |
| `METRICS_SERVER_ENABLED` | `true` | Enable the dedicated metrics listener |
| `LOG_LEVEL` | `INFO` | Python log level |
| `ENABLE_AUTH` | `true` | Enable the `coding-client` auth/tenant middleware |
| `ENABLE_DOCS` | `false` | Setting exists, but `/docs` and `/openapi.json` are always mounted |
| `DATABASE_URL` | `""` | PostgreSQL connection string; required in production, not actively queried (the DB layer is not wired) |
| `REDIS_URL` | `""` | Redis connection string; required in production; backs the validation cache and the durable scan queue |
| `CONTAINERS_SERVICE_URL` | `""` | Base URL of `coding-containers`; required in production |
| `DOCKER_REGISTRY_URL` | `""` | Registry used for image scans; required in production |
| `DOCKER_REGISTRY_USERNAME` | `registry` | Registry username for image scans |
| `DOCKER_REGISTRY_PASSWORD` | `""` | Registry password for image scans |
| `WORKSPACE_ROOT` | `/workspace` | Workspace root inside a `coding-containers` workspace pod |
| `GITHUB_SERVICE_URL` | `""` | Optional; needed only for `/upgrade` and `/upgrade-major` with `commit=true` or `open_pr=true` |
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |
| `NVD_API_KEY` | _(unset)_ | Optional NVD API key |
| `OTEL_ENDPOINT` | `""` | Present in `Settings` but not wired; tracing reads `OTLP_TRACES_ENDPOINT` |
| `DEFAULT_TENANT_ID` | _(unset)_ | Fallback tenant for credential-less requests from trusted networks. Read by `coding-client`, not `Settings`; unset means such requests are rejected |
| `OTLP_TRACES_ENDPOINT` | _(unset)_ | Tracing exporter URL including `/v1/traces`, read by `coding-client`'s `setup_tracing`; unset disables tracing |

### Scanning and worker tuning

| Variable | Default | Description |
|---|---|---|
| `TRIVY_SCAN_TIMEOUT` | `300` | Trivy scan timeout in seconds |
| `GRYPE_SCAN_TIMEOUT` | `300` | Grype scan timeout in seconds |
| `SYFT_SCAN_TIMEOUT` | `180` | Syft scan timeout in seconds |
| `SECURITY_SCAN_BUDGET_SECONDS` | `60.0` | Synchronous security-scan wall-clock budget |
| `SECURITY_FETCH_TIMEOUT_SECONDS` | `120.0` | File-fetch timeout for scans |
| `SECURITY_ASYNC_SCAN_BUDGET_SECONDS` | `300.0` | Async security-scan wall-clock budget |
| `SECURITY_SCAN_TASK_TTL_SECONDS` | `86400` | Redis TTL for completed async scan records |
| `SECURITY_SCAN_STALE_AFTER_SECONDS` | `600.0` | Age after which a running async job is reported as stale/failed |
| `DEPENDENCY_SCAN_ASYNC_BUDGET_SECONDS` | `300.0` | Async dependency-scan wall-clock budget |
| `SCAN_WORKER_ENABLED` | `true` | Enable the Redis Streams scan worker |
| `SCAN_WORKER_CONCURRENCY` | `2` | Concurrent worker read loops |
| `SCAN_STREAM` | `security:scan:jobs` | Redis stream name for scan jobs |
| `SCAN_CONSUMER_GROUP` | `coding-security-scanner` | Consumer group name |
| `SCAN_CONSUMER_NAME` | `worker-0` | Consumer name |
| `SCAN_WORKER_BLOCK_MS` | `5000` | Stream read block time in milliseconds |
| `SCAN_RECLAIM_INTERVAL_SECONDS` | `60.0` | Pending-message reclaim interval |
| `SCAN_RECLAIM_MIN_IDLE_SECONDS` | `900` | Minimum idle time before a pending message is reclaimed |
| `SCAN_MAX_DELIVERIES` | `3` | Maximum deliveries before a job is dead-lettered |
| `SCAN_STREAM_MAXLEN` | `10000` | Approximate stream length cap |
| `OSV_OFFLINE_DB_DIR` | `/opt/osv-db` | Directory of the baked offline OSV database |
| `OSV_DB_MAX_AGE_DAYS` | `10` | Age at which `/health` reports the baked OSV database as stale |

## Dependencies on Other Services

- **coding-containers** -- resolves container names to codebase paths and file listings. The URL comes from `CONTAINERS_SERVICE_URL` (required in production; `http://coding-containers:8691` in-cluster). All container-scoped endpoints depend on this.
- **Redis** -- `REDIS_URL` is required in production by the settings validator. Redis caches `SecurityValidationResult` objects (1-hour TTL) and backs the durable async-scan stream/worker.
- **OSV data** -- in production the dependency analyzer reads the **baked offline OSV database**
  (`/opt/osv-db`, built at image time from the PyPI, crates.io and npm `all.zip` exports) because
  the pod's egress to `api.osv.dev` is blocked by the ambient-mesh policy by design. The live OSV
  API is used only where egress exists (tests / local). A scan whose ecosystem has no baked DB
  reports those packages as UNCHECKED and sets `scan_degraded` -- it never reports them clean.

## Supported Languages

**Code vulnerability scanning:** Python, Java, JavaScript, TypeScript, C, C++, Go, Rust, C#, PHP, Ruby

**Dependency extraction:** pip/poetry/pipenv/uv/conda, npm/yarn/pnpm/bun, cargo, maven/gradle, gem/bundler, go mod, composer, nuget/dotnet

**System dependency managers:** apt, yum, dnf, pacman, zypper, apk, brew, choco

## Running Locally

```bash
# With uv (ENVIRONMENT=testing skips the production required-env check)
uv sync
ENVIRONMENT=testing PYTHONPATH=src uv run uvicorn main:app --host 0.0.0.0 --port 8693

# With Docker
docker compose up coding-security
```

## Directory Structure

```
src/
  main.py                  -- Uvicorn entrypoint (creates app)
  app_factory.py           -- FastAPI app constructor, lifespan, middleware, router mounting
  dependencies.py          -- DI container (SystemSecurityService singleton)
  auth/
    tenant.py              -- re-exports coding-client tenant middleware (X-Tenant-Id, trusted-CIDR fallback)
  config/
    settings.py            -- Pydantic BaseSettings (env vars)
    security_config.py     -- Dangerous-pattern defs, sandbox config presets
  routers/
    security/              -- /api/security/* endpoints
    dependencies.py        -- /api/dependencies/* endpoints
    system_dependencies.py -- /api/dependencies/system/* endpoints
  services/
    security_service.py    -- SystemSecurityService (code validation, caching)
    security_detector.py   -- Multi-language vulnerability pattern matching
    security_scan_service.py -- Container-scoped scan orchestrator
    dependency_analyzer.py -- Package manifest parsing + OSV.dev CVE lookups
    system_dependency_manager.py -- OS-level dep detection + script generation
    container_registry.py  -- HTTP client to coding-containers service
    ...
  models/                  -- Pydantic request/response models
  utils/                   -- Parameter + container validation helpers
  db/                      -- (placeholder, not actively used)
```

## Dev Tooling

- **Linter:** ruff (`ruff check`, `ruff format`)
- **Type checker:** ty
- **Tests:** pytest + pytest-asyncio + pytest-cov
- **Security audit:** detect-secrets, pip-audit

```bash
uv sync --group dev
uv run ruff check src/ tests/
uv run ty check src/
uv run pytest
```

`coding-client` is consumed as a pinned git dependency using `[tool.uv.sources]`.
The other packages resolve from public PyPI.
`pip-audit` may report that `coding-client` was not found on PyPI: this means
the public vulnerability database cannot audit the private distribution, not
that installation failed. Its public transitive dependencies are still audited.
Adding an extra package index does not supply vulnerability records for private
packages.

To refresh dependencies, run `uv lock --upgrade`, then run the checks above and
`scripts/pip-audit.sh`. The latest compatible releases can differ from the latest
major releases: `coding-client` requires Pydantic AI 1.x, which requires FastMCP
3.x and MCP 1.x, while its xAI SDK dependency requires `packaging<26`.

## CI/CD

`.github/workflows/ci.yml` calls the public `nonagenticai/ci-workflows/python-service.yml`
workflow on GitHub-hosted runners: lint, type-check and tests, an amd64 image build, a smoke test
that requires a fresh baked OSV database, and a push to
`ghcr.io/nonagenticai/coding-security`. There is no deploy job -- Flux watches this service's
ImagePolicy and rolls the image when it changes. A weekly scheduled rebuild keeps the baked OSV
database current.

## Runtime Dependencies

Key runtime dependencies (see `pyproject.toml` for full list):
- FastAPI + Uvicorn + Gunicorn
- Pydantic + pydantic-settings
- httpx (HTTP client for coding-containers and OSV.dev)
- redis (async Redis client)
- coding-client (shared auth/tenant middleware, tracing)
- OpenTelemetry (optional tracing)
- packaging (version comparison for dependency analysis)

## Security

Report vulnerabilities privately through the repository's Security tab — see
[`SECURITY.md`](SECURITY.md). Do not open a public issue for a security problem.

## Contributing

Issues and pull requests are welcome. See
[`CONTRIBUTING.md`](https://github.com/nonagenticai/.github/blob/main/CONTRIBUTING.md) for the
organisation-wide rules; setup, test and lint commands are in this README. Commits carry DCO
sign-off.

## Licensing

The code in this repository is Apache-2.0 and needs no licence key to build, test or run.
Licence tokens are an **optional** identity source: with `LICENSE_INTROSPECT_URL` unset (the
default), a `Bearer` licence cannot be introspected, and callers authenticate through the
platform's mesh-forwarded identity instead. With the URL set, every licence token is
introspected against the licences service, and an unreachable service yields no identity
(401) — never an admission.

The licensing stack is public too — [`licenses`](https://github.com/nonagenticai/licenses)
(entitlements, plans and tokens) and
[`license-authz`](https://github.com/nonagenticai/license-authz) (the Envoy `ext_authz`
enforcement point). Neither is required to run this code.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
