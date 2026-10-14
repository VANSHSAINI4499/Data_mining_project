# 0008. uv for Python, npm for the frontend

- Status: accepted
- Date: 2026-10-14

## Context

We need reproducible, locked environments on Windows, macOS, Linux, and in Docker.

## Decision

We will use `uv` (`pyproject.toml` + `uv.lock`, dev tools in a PEP 735 dependency group) and `npm` with a committed `package-lock.json`.

## Alternatives considered

pip-tools, Poetry, pnpm.

## Consequences

- Fast, locked installs; `uv sync --frozen` in Docker.
- Developers need uv (`pip install --user uv` works); the pip fallback is `pip install -e . --group dev` (pip >= 25.1).
