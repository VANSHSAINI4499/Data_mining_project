# 0009. Phase 1 dependency version baseline

- Status: accepted
- Date: 2026-10-14
- Related: [TECH_STACK.md](../../TECH_STACK.md); resolves open decision OD-12

## Context

TECH_STACK.md named expected major lines before any package was installed. Installing the
then-current stable releases in Phase 1 produced several newer majors than anticipated, and the
build machine had no Docker.

## Decision

We lock the versions resolved on 2026-10-14 (`backend/uv.lock`, `frontend/package-lock.json`).
Notable differences from the original plan:

| Component | Planned | Locked |
|---|---|---|
| React Router | 7 | 8.4 (declarative `BrowserRouter`/`Routes` API, same usage) |
| TypeScript | 5.x | 6.0 |
| Vite / Vitest | current | 8.3 / 5.0 |
| MSW | (unspecified) | 3.0 (listen option is `onUnhandledFrame`, not `onUnhandledRequest`) |
| SQLAlchemy | 2.0 | 2.1 |
| FastAPI | current 0.x | 0.143 |
| Node.js | 24 LTS | 24 in Docker; `engines >= 22.22` (React Router 8 minimum); verified on 22.23 |
| PostgreSQL | 17 | 17 in Docker; Phase 1 tests ran on native 18.6 (Scoop) |

Recharts is not installed until Phase 6.

## Alternatives considered

Pinning to the originally named majors (older releases, no benefit for a new project).

## Consequences

- Starlette 1.x warns that `TestClient` over `httpx` is deprecated in favour of `httpx2`. The
  warning is visible in test output; switching is deferred until it becomes an error, because it
  changes a dev dependency.
- PostgreSQL 17 (Docker) has not yet been exercised by the test suite; run it once Docker is
  available.
