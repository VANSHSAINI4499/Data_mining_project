# 0001. Record architecture decisions

- Status: accepted
- Date: 2026-10-14

## Context

Decisions in this project span sessions and contributors (including AI assistants). Without a written record, choices get re-litigated or silently reversed.

## Decision

We will record significant technical decisions as short ADRs in `docs/decisions/` using the Nygard format and the process in [README.md](README.md).

## Alternatives considered

Wiki pages (drift from code); no records (decisions lost).

## Consequences

- One Markdown file per decision; superseded rather than edited.
- Small overhead per significant change; dev-only tooling is exempt.
