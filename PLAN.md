# coding-security — Extraction Plan

## Purpose
Compact, well-bounded security domain. Owns vulnerability scanning, security detection, and dependency analysis.

## Port: 8693

---

## Endpoints

| Route Prefix | Source Router | Source Endpoint File |
|---|---|---|
| `/api/security` | `security` | `src/app/api/endpoints/security.py` |
| `/api/dependencies` | `dependencies` | `src/app/api/endpoints/dependencies.py` |
| `/api/dependencies/system` | `system_dependencies` | `src/app/api/endpoints/system_dependencies.py` |

## Services to Extract

| Monolith Service | Target Location |
|---|---|
| `services/security_detector.py` | `src/services/security_detector.py` |
| `services/unified_security_scanner.py` | `src/services/unified_security_scanner.py` |
| `services/bug_analysis.py` | `src/services/bug_analysis.py` |

## DB Tables Owned
- ExternalPackage

## Dependencies
- coding-client (shared models, auth, DB)
