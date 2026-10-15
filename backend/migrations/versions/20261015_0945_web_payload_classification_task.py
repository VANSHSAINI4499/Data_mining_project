"""Allow the web_payload_classification task in the model registry.

Revision ID: 3c1e9a7b5d20
Revises: 98a6e81b76e5
Create Date: 2026-10-15 09:45:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "3c1e9a7b5d20"
down_revision: str | None = "98a6e81b76e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW = "task IN ('classification', 'anomaly', 'web_payload_classification')"
OLD = "task IN ('classification', 'anomaly')"


def _replace(table: str, condition: str) -> None:
    op.drop_constraint(op.f(f"ck_{table}_task"), table, type_="check")
    op.create_check_constraint(op.f(f"ck_{table}_task"), table, condition)


def upgrade() -> None:
    _replace("ml_training_run", NEW)
    _replace("ml_model", NEW)


def downgrade() -> None:
    # Fails if web_payload_classification rows exist; remove them first (development only).
    _replace("ml_model", OLD)
    _replace("ml_training_run", OLD)
