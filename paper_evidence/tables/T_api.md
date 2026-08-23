# A9 — Public API and CLI surface

## REST routes (51)

| method | path | defined in |
|---|---|---|
| DELETE | `` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| GET | `` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| POST | `` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| GET | `/algorithms` | `packages/qubit-api/src/qubit_api/routers/registry.py` |
| GET | `/assets/{asset_id}` | `packages/qubit-api/src/qubit_api/routers/assets.py` |
| GET | `/assets/{asset_id}/hndl` | `packages/qubit-api/src/qubit_api/routers/risk.py` |
| GET | `/assets/{asset_id}/recommendation` | `packages/qubit-api/src/qubit_api/routers/recommendation.py` |
| GET | `/auth/whoami` | `packages/qubit-api/src/qubit_api/auth.py` |
| GET | `/events` | `packages/qubit-api/src/qubit_api/routers/jobs.py` |
| GET | `/health` | `packages/qubit-api/src/qubit_api/routers/meta.py` |
| GET | `/health/deps` | `packages/qubit-api/src/qubit_api/routers/meta.py` |
| GET | `/jobs` | `packages/qubit-api/src/qubit_api/routers/jobs.py` |
| GET | `/jobs/{job_id}` | `packages/qubit-api/src/qubit_api/routers/jobs.py` |
| POST | `/jobs/{job_id}/cancel` | `packages/qubit-api/src/qubit_api/routers/jobs.py` |
| GET | `/jobs/{job_id}/events` | `packages/qubit-api/src/qubit_api/routers/jobs.py` |
| GET | `/languages` | `packages/qubit-api/src/qubit_api/routers/registry.py` |
| GET | `/meta/agility-policy` | `packages/qubit-api/src/qubit_api/routers/meta.py` |
| GET | `/meta/migration-kb` | `packages/qubit-api/src/qubit_api/routers/meta.py` |
| POST | `/migrate/patches/{patch_id}/apply` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| POST | `/migrate/patches/{patch_id}/review` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| GET | `/migrate/plans` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| POST | `/migrate/plans` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| GET | `/migrate/plans/{plan_id}/graph` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| GET | `/migrate/plans/{plan_id}/queue` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| POST | `/migrate/plans/{plan_id}/run` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| POST | `/migrate/tasks/{task_id}/advise` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| POST | `/migrate/tasks/{task_id}/generate` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| GET | `/migrate/tasks/{task_id}/governance` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| GET | `/migrate/tasks/{task_id}/patches` | `packages/qubit-api/src/qubit_api/routers/migrate.py` |
| GET | `/overview` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| GET | `/risk/runs/{risk_run_id}` | `packages/qubit-api/src/qubit_api/routers/risk.py` |
| GET | `/risk/timeline` | `packages/qubit-api/src/qubit_api/routers/risk.py` |
| DELETE | `/scans` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/scans` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| DELETE | `/scans/{scan_id}` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/scans/{scan_id}` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/scans/{scan_id}/assets` | `packages/qubit-api/src/qubit_api/routers/assets.py` |
| GET | `/scans/{scan_id}/cbom` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/scans/{scan_id}/cnsa2` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/scans/{scan_id}/diff` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| POST | `/scans/{scan_id}/risk/run` | `packages/qubit-api/src/qubit_api/routers/risk.py` |
| GET | `/scans/{scan_id}/risk/summary` | `packages/qubit-api/src/qubit_api/routers/risk.py` |
| GET | `/scans/{scan_id}/risk/timeline` | `packages/qubit-api/src/qubit_api/routers/risk.py` |
| GET | `/scans/{scan_id}/sarif` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/scans/{scan_id}/summary` | `packages/qubit-api/src/qubit_api/routers/scans.py` |
| GET | `/version` | `packages/qubit-api/src/qubit_api/routers/meta.py` |
| DELETE | `/{project_id}` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| GET | `/{project_id}` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| PATCH | `/{project_id}` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| GET | `/{project_id}/scans` | `packages/qubit-api/src/qubit_api/routers/projects.py` |
| GET | `/{project_id}/trends` | `packages/qubit-api/src/qubit_api/routers/projects.py` |

## CLI commands (5)

| command | entry point |
|---|---|
| `qubit report` | qubit-cli |
| `qubit scan` | qubit-cli |
| `qubit scan-network` | qubit-cli |
| `qubit scan-vault` | qubit-cli |
| `qubit version` | qubit-cli |
