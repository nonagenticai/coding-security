# coding-security

[![CI](https://github.com/nonagenticai/coding-security/actions/workflows/ci.yml/badge.svg)](https://github.com/nonagenticai/coding-security/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nonagenticai/coding-security)](https://github.com/nonagenticai/coding-security/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Static security analysis service for the Code Graph Helper platform. Scans source code for security vulnerabilities, analyzes project dependencies for known CVEs, detects missing system-level dependencies, and generates sandbox configurations for safe code execution.

This service is part of the `code_graph_helper` microservices suite and operates on "containers" -- named codebases managed by the `coding-containers` service.

## Port: 8693

## Authentication

Istio ext_authz validates license tokens on incoming requests. The `coding-client` library provides `AuthMiddleware` which reads Istio-injected headers (enabled when `ENABLE_AUTH=true`). Tenant isolation is enforced via the `X-Tenant-Id` header set by the ext_authz filter after license validation; the service falls back to `DEFAULT_TENANT_ID` if the header is absent. No direct Keycloak or JWT validation occurs in this service.

## Architecture

```
coding-security (FastAPI, port 8693)
  |
  +-- /api/security/*          -- Code vulnerability scanning + sandbox configs
  +-- /api/dependencies/*      -- Package dependency analysis (CVEs, outdated, risk)
  +-- /api/dependencies/system/* -- System-level dependency detection + script generation
  |
  +-- coding-containers:8691   -- HTTP calls to resolve container metadata
  +-- Redis                    -- Optional cache for security validation results
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

All routes require tenant identification via `X-Tenant-Id` header (falls back to `DEFAULT_TENANT_ID` env var).

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

Environment variables (all optional with defaults):

| Variable | Default | Description |
|---|---|---|
| `SERVICE_NAME` | `coding-security` | Service name for logging and telemetry |
| `VERSION` | `1.0.0` | Service version |
| `ENVIRONMENT` | `production` | Environment name |
| `PORT` | `8693` | Listening port |
| `LOG_LEVEL` | `INFO` | Python log level |
| `ENABLE_AUTH` | `true` | Enable Istio auth middleware |
| `ENABLE_DOCS` | `false` | Enable OpenAPI docs (setting exists but docs are always mounted in app_factory) |
| `DEFAULT_TENANT_ID` | `n8n-dev` | Fallback tenant when no header present |
| `DATABASE_URL` | `postgresql+psycopg://...` | PostgreSQL connection (for future use, not actively queried) |
| `REDIS_URL` | `redis://redis:6379/0` | Redis for caching security validation results |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(unset)_ | OpenTelemetry collector endpoint; telemetry disabled if unset |
| `CONTAINERS_SERVICE_URL` | `http://coding-containers:8691` | URL of coding-containers service for container metadata lookups |
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |

## Dependencies on Other Services

- **coding-containers** (`http://coding-containers:8691`) -- resolves container names to codebase paths, file listings. All container-scoped endpoints depend on this.
- **Redis** -- optional; caches `SecurityValidationResult` objects (1-hour TTL). Service operates without it.
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
# With uv
uv sync
uv run uvicorn main:app --host 0.0.0.0 --port 8693

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
    tenant.py              -- require_tenant dependency (X-Tenant-Id extraction)
  config/
    settings.py            -- Pydantic BaseSettings (env vars)
    security_config.py     -- Dangerous-pattern defs, sandbox config presets
  routers/
    security.py            -- /api/security/* endpoints
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

GitHub Actions workflow: `ruff + ty → build amd64 → smoke test → push`

Image pushed to `192.168.1.114:5000/coding-security:sha-<commit>`, promoted to `:latest` on success. Flux auto-deploys to K3s.

## Runtime Dependencies

Key runtime dependencies (see `pyproject.toml` for full list):
- FastAPI + Uvicorn + Gunicorn
- Pydantic + pydantic-settings
- httpx (HTTP client for coding-containers and OSV.dev)
- redis (async Redis client)
- coding-client (shared auth middleware -- Istio header extraction)
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
