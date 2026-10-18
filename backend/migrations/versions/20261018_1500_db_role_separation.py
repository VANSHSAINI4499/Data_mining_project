"""Database role separation: privileged operations behind SECURITY DEFINER functions.

The application role is meant to be DML-only (SECURITY_REQUIREMENTS.md §6): no DDL, and no
UPDATE/DELETE on ``audit_log``. Two runtime operations need more than that, so they run as
the function owner (the migration role) with a fixed ``search_path``:

- ``ensure_event_partitions`` creates monthly ``fact_security_event`` partitions;
- ``prune_audit_log(cutoff)`` deletes audit records older than ``cutoff`` and refuses any
  cutoff newer than 364 days (settings require >= 365), so the application cannot erase
  recent audit history.

EXECUTE is revoked from PUBLIC; ``cti db grant-app-role`` grants it to the application role.

Revision ID: 9d3e5a7c2b18
Revises: 7b2d4f9e1a63
Create Date: 2026-10-18 15:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "9d3e5a7c2b18"
down_revision: str | None = "7b2d4f9e1a63"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENSURE = "ensure_event_partitions(timestamptz, timestamptz)"

PRUNE_AUDIT_LOG_SQL = r"""
CREATE FUNCTION prune_audit_log(p_cutoff timestamptz)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted bigint;
BEGIN
    -- 364, not 365: one day of tolerance for clock skew; settings enforce >= 365 days.
    IF p_cutoff IS NULL OR p_cutoff > now() - interval '364 days' THEN
        RAISE EXCEPTION 'prune_audit_log: cutoff % is newer than the minimum retention', p_cutoff;
    END IF;
    DELETE FROM audit_log WHERE occurred_at < p_cutoff;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$
"""


def upgrade() -> None:
    op.execute(f"ALTER FUNCTION {ENSURE} SECURITY DEFINER SET search_path = public, pg_temp")
    op.execute(f"REVOKE EXECUTE ON FUNCTION {ENSURE} FROM PUBLIC")
    op.execute(PRUNE_AUDIT_LOG_SQL)
    op.execute("REVOKE EXECUTE ON FUNCTION prune_audit_log(timestamptz) FROM PUBLIC")


def downgrade() -> None:
    op.execute("DROP FUNCTION prune_audit_log(timestamptz)")
    op.execute(f"GRANT EXECUTE ON FUNCTION {ENSURE} TO PUBLIC")
    op.execute(f"ALTER FUNCTION {ENSURE} SECURITY INVOKER RESET search_path")
