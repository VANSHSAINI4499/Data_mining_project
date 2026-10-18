"""Allow analyst feedback on web payload predictions (web_payload_result).

Revision ID: 5f8a1c3e9d47
Revises: 9d3e5a7c2b18
Create Date: 2026-10-18 16:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "5f8a1c3e9d47"
down_revision: str | None = "9d3e5a7c2b18"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW = (
    "target_type IN ('event', 'classification_result', 'anomaly_result', 'indicator_match', "
    "'alert', 'web_payload_result')"
)
OLD = (
    "target_type IN ('event', 'classification_result', 'anomaly_result', 'indicator_match', "
    "'alert')"
)


def _replace(condition: str) -> None:
    op.drop_constraint(op.f("ck_analyst_feedback_target_type"), "analyst_feedback", type_="check")
    op.create_check_constraint(
        op.f("ck_analyst_feedback_target_type"), "analyst_feedback", condition
    )


def upgrade() -> None:
    _replace(NEW)


def downgrade() -> None:
    # Fails if feedback on web payload results exists; feedback is append-only ground truth,
    # so remove it deliberately first (development only).
    _replace(OLD)
