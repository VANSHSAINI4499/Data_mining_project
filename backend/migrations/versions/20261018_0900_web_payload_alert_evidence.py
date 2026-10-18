"""Allow web_payload_result as alert evidence.

Revision ID: 7b2d4f9e1a63
Revises: 4e1ff4ad3cf5
Create Date: 2026-10-18 09:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "7b2d4f9e1a63"
down_revision: str | None = "4e1ff4ad3cf5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW = (
    "evidence_type IN ('event', 'classification_result', 'anomaly_result', 'indicator_match', "
    "'web_payload_result')"
)
OLD = "evidence_type IN ('event', 'classification_result', 'anomaly_result', 'indicator_match')"


def _replace(condition: str) -> None:
    op.drop_constraint(op.f("ck_alert_evidence_evidence_type"), "alert_evidence", type_="check")
    op.create_check_constraint(op.f("ck_alert_evidence_evidence_type"), "alert_evidence", condition)


def upgrade() -> None:
    _replace(NEW)


def downgrade() -> None:
    # Fails if web_payload_result evidence exists; remove those rows first (development only).
    _replace(OLD)
