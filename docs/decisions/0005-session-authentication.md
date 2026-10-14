# 0005. Server-side sessions with CSRF protection and three roles

- Status: accepted
- Date: 2026-10-14

## Context

A same-origin browser SPA needs authentication that can be revoked immediately and is not readable by injected scripts.

## Decision

We will use opaque 256-bit session tokens in an `HttpOnly`, `SameSite=Strict` cookie scoped to `/api`, stored server-side only as HMAC-SHA-256 digests. A separate CSRF token is required in `X-CSRF-Token` for state-changing requests and is rotated by `GET /auth/me`. Roles are `viewer` < `analyst` < `admin`, enforced by a `require_role` dependency on every route.

## Alternatives considered

JWT bearer tokens in browser storage (exposed to XSS, hard to revoke); external SSO (future).

## Consequences

- Immediate revocation (logout, deactivation, role change, password reset).
- One database lookup per request (acceptable at MVP scale).
- Every failed login returns the same generic 401; lockout is visible only in the audit log.
