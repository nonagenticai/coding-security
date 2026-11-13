# Operation ID Plan: coding-security

## Note
`coding-client` was originally requested but it is a shared library with no routes.
This plan covers `coding-security` as a substitute.

## Files to Edit
- `src/app_factory.py` (2 app-level routes defined inside `_include_routers()`)
- `src/routers/security.py` (10 routes)
- `src/routers/dependencies.py` (5 routes, mounted at TWO prefixes -- see notes)
- `src/routers/system_dependencies.py` (5 routes)

## Router Mount Notes

The `dependencies` router is mounted twice in `app_factory.py`:
```python
app.include_router(dependencies_router, prefix="/api/dependencies", ...)
app.include_router(dependencies_router, prefix="/api/security/dependencies", ...)
```
Since both mounts use the same router object, the `operation_id` values will be
shared. FastAPI will raise a duplicate operation_id error for the second mount.

**Fix:** Add `include_in_schema=False` to the second mount:
```python
app.include_router(
    dependencies_router,
    prefix="/api/security/dependencies",
    tags=["Dependencies"],
    include_in_schema=False,
)
```

## Mapping Table

### app_factory.py (app-level, no prefix)

| Method | Effective Path | Function | operation_id |
|--------|---------------|----------|--------------|
| GET | `/health` | `health` | `health_check` |
| GET | `/` | `root` | `get_root` |

### security.py (prefix `/api/security`)

| Method | Effective Path | Function | operation_id |
|--------|---------------|----------|--------------|
| POST | `/api/security/validate` | `validate_code_security` | `validate_code_security` |
| GET | `/api/security/sandbox-config/{language}/{security_level}` | `get_sandbox_config` | `get_sandbox_config` |
| POST | `/api/security/analyze-vulnerabilities` | `analyze_security_vulnerabilities` | `analyze_vulnerabilities` |
| GET | `/api/security/patterns` | `get_security_patterns` | `list_security_patterns` |
| POST | `/api/security/scan/{container_name}` | `scan_container_security` | `scan_container_security` |
| GET | `/api/security/report/{container_name}` | `get_container_security_report` | `get_security_report` |
| POST | `/api/security/scan/{container_name}/quick` | `quick_scan_container_security` | `quick_scan_container_security` |
| POST | `/api/security/scan/{container_name}/image` | `scan_container_image` | `scan_container_image` |
| POST | `/api/security/sbom/{container_name}` | `generate_container_sbom` | `generate_sbom` |
| POST | `/api/security/sbom/{container_name}/vulnerabilities` | `scan_sbom_vulnerabilities` | `scan_sbom_vulnerabilities` |

### dependencies.py (prefix `/api/dependencies`)

| Method | Effective Path | Function | operation_id |
|--------|---------------|----------|--------------|
| GET | `/api/dependencies/{container_name}` | `get_dependencies` | `get_container_dependencies` |
| GET | `/api/dependencies/{container_name}/outdated` | `get_outdated_packages` | `list_outdated_packages` |
| GET | `/api/dependencies/{container_name}/vulnerable` | `get_vulnerable_packages` | `list_vulnerable_packages` |
| GET | `/api/dependencies/{container_name}/report` | `get_dependency_report` | `get_dependency_report` |
| POST | `/api/dependencies/{container_name}/scan` | `trigger_dependency_scan` | `scan_container_dependencies` |

### system_dependencies.py (prefix `/api/dependencies/system`)

| Method | Effective Path | Function | operation_id |
|--------|---------------|----------|--------------|
| GET | `/api/dependencies/system/detect` | `detect_dependencies` | `detect_system_dependencies` |
| POST | `/api/dependencies/system/generate-script` | `generate_install_script` | `generate_install_script` |
| POST | `/api/dependencies/system/generate-dockerfile` | `generate_dockerfile_snippet` | `generate_dockerfile_snippet` |
| POST | `/api/dependencies/system/generate-ci-config` | `generate_ci_config` | `generate_ci_config` |
| GET | `/api/dependencies/system/list-known` | `list_known_dependencies` | `list_known_system_dependencies` |

## Total: 22 routes (2 app-level + 10 security + 5 dependencies + 5 system-dependencies)

## Uniqueness Check

All 22 operation_ids are unique:
`health_check`, `get_root`, `validate_code_security`, `get_sandbox_config`,
`analyze_vulnerabilities`, `list_security_patterns`, `scan_container_security`,
`get_security_report`, `quick_scan_container_security`, `scan_container_image`,
`generate_sbom`, `scan_sbom_vulnerabilities`, `get_container_dependencies`,
`list_outdated_packages`, `list_vulnerable_packages`, `get_dependency_report`,
`scan_container_dependencies`, `detect_system_dependencies`,
`generate_install_script`, `generate_dockerfile_snippet`,
`generate_ci_config`, `list_known_system_dependencies`

## Execution Steps
```bash
cd /Users/mini1/Movies/code_graph_helper/coding-security && git pull --rebase
```
1. Fix the duplicate mount issue in `src/app_factory.py` (add `include_in_schema=False`)
2. Add `operation_id=` to the 2 app-level routes in `src/app_factory.py`
3. Add `operation_id=` to the 10 routes in `src/routers/security.py`
4. Add `operation_id=` to the 5 routes in `src/routers/dependencies.py`
5. Add `operation_id=` to the 5 routes in `src/routers/system_dependencies.py`
6. Validate uniqueness: `grep -r 'operation_id=' src/ | sort | uniq -d` (should be empty)
7. `pre-commit run --all-files`
8. `pytest`
9. `git commit` and `git push`
