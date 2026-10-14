"""Threat intelligence, ATT&CK, correlation, alerts, cases, feedback (Phase 5).

DATABASE_DESIGN.md §3.4 and §3.7. Alerts have one open alert per dedup key (partial unique
index); case timeline and analyst feedback are append-only by application convention.

Revision ID: e0c9d6109e42
Revises: f0d5d5612edb
Create Date: 2026-10-14 21:19:18.930856+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e0c9d6109e42"
down_revision: str | None = "f0d5d5612edb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_technique",
        sa.Column("technique_id", sa.Text(), nullable=False),
        sa.Column("stix_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("parent_technique_id", sa.Text(), nullable=True),
        sa.Column("attack_version", sa.Text(), nullable=True),
        sa.Column("deprecated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("technique_id", name=op.f("pk_attack_technique")),
    )
    op.create_table(
        "ti_feed",
        sa.Column("feed_id", sa.UUID(), nullable=False),
        sa.Column("feed_key", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("feed_type", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("collection_id", sa.Text(), nullable=True),
        sa.Column("reliability", sa.Text(), server_default=sa.text("'F'"), nullable=False),
        sa.Column(
            "default_confidence", sa.SmallInteger(), server_default=sa.text("50"), nullable=False
        ),
        sa.Column("default_ttl_days", sa.Integer(), server_default=sa.text("90"), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("poll_interval_minutes", sa.Integer(), nullable=True),
        sa.Column("credentials_ref", sa.Text(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "feed_type IN ('manual', 'csv_file', 'stix_file', 'taxii')",
            name=op.f("ck_ti_feed_feed_type"),
        ),
        sa.CheckConstraint(
            "reliability IN ('A','B','C','D','E','F')", name=op.f("ck_ti_feed_reliability")
        ),
        sa.CheckConstraint(
            "default_confidence BETWEEN 0 AND 100", name=op.f("ck_ti_feed_default_confidence")
        ),
        sa.PrimaryKeyConstraint("feed_id", name=op.f("pk_ti_feed")),
        sa.UniqueConstraint("feed_key", name=op.f("uq_ti_feed_feed_key")),
    )
    op.create_table(
        "analyst_feedback",
        sa.Column("feedback_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("corrected_category_id", sa.SmallInteger(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("analyst_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "target_type IN ('event', 'classification_result', 'anomaly_result', 'indicator_match', 'alert')",
            name=op.f("ck_analyst_feedback_target_type"),
        ),
        sa.CheckConstraint(
            "verdict IN ('true_positive', 'false_positive', 'benign_unusual', 'needs_more_info')",
            name=op.f("ck_analyst_feedback_verdict"),
        ),
        sa.ForeignKeyConstraint(
            ["analyst_id"],
            ["app_user.user_id"],
            name=op.f("fk_analyst_feedback_analyst_id_app_user"),
        ),
        sa.ForeignKeyConstraint(
            ["corrected_category_id"],
            ["dim_attack_category.attack_category_id"],
            name=op.f("fk_analyst_feedback_corrected_category_id_dim_attack_category"),
        ),
        sa.PrimaryKeyConstraint("feedback_id", name=op.f("pk_analyst_feedback")),
    )
    op.create_index(
        op.f("ix_analyst_feedback_target_type_target_id"),
        "analyst_feedback",
        ["target_type", "target_id"],
        unique=False,
    )
    op.create_table(
        "attack_category_technique",
        sa.Column("attack_category_id", sa.SmallInteger(), nullable=False),
        sa.Column("technique_id", sa.Text(), nullable=False),
        sa.Column("mapping_confidence", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("mapping_version", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "mapping_confidence IN ('low', 'medium', 'high')",
            name=op.f("ck_attack_category_technique_confidence"),
        ),
        sa.ForeignKeyConstraint(
            ["attack_category_id"],
            ["dim_attack_category.attack_category_id"],
            name=op.f("fk_attack_category_technique_attack_category_id_dim_attack_category"),
        ),
        sa.ForeignKeyConstraint(
            ["technique_id"],
            ["attack_technique.technique_id"],
            name=op.f("fk_attack_category_technique_technique_id_attack_technique"),
        ),
        sa.PrimaryKeyConstraint(
            "attack_category_id", "technique_id", name=op.f("pk_attack_category_technique")
        ),
    )
    op.create_table(
        "correlation_rule",
        sa.Column("rule_id", sa.UUID(), nullable=False),
        sa.Column("rule_key", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("base_severity", sa.Text(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "base_severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_correlation_rule_severity"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["app_user.user_id"],
            name=op.f("fk_correlation_rule_created_by_app_user"),
        ),
        sa.PrimaryKeyConstraint("rule_id", name=op.f("pk_correlation_rule")),
        sa.UniqueConstraint(
            "rule_key", "version", name=op.f("uq_correlation_rule_rule_key_version")
        ),
    )
    op.create_table(
        "incident_case",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'open'"), nullable=False),
        sa.Column("disposition", sa.Text(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("assigned_to", sa.UUID(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("opened_by", sa.UUID(), nullable=True),
        sa.Column(
            "opened_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "disposition IS NULL OR disposition IN ('confirmed_incident', 'false_positive', 'benign_true_positive', 'inconclusive')",
            name=op.f("ck_incident_case_disposition"),
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_incident_case_severity"),
        ),
        sa.CheckConstraint(
            "status <> 'closed' OR disposition IS NOT NULL",
            name=op.f("ck_incident_case_closed_needs_disposition"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'closed')", name=op.f("ck_incident_case_status")
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to"],
            ["app_user.user_id"],
            name=op.f("fk_incident_case_assigned_to_app_user"),
        ),
        sa.ForeignKeyConstraint(
            ["opened_by"], ["app_user.user_id"], name=op.f("fk_incident_case_opened_by_app_user")
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_incident_case")),
    )
    op.create_table(
        "alert",
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column("rule_id", sa.UUID(), nullable=False),
        sa.Column("dedup_key", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'new'"), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("primary_entity_type", sa.Text(), nullable=False),
        sa.Column("primary_entity_value", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=False),
        sa.Column("risk_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("assigned_to", sa.UUID(), nullable=True),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("related_alert_id", sa.UUID(), nullable=True),
        sa.Column("dismiss_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('new', 'acknowledged', 'in_review', 'escalated', 'dismissed', 'closed')",
            name=op.f("ck_alert_status"),
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name=op.f("ck_alert_risk_score")),
        sa.ForeignKeyConstraint(
            ["assigned_to"], ["app_user.user_id"], name=op.f("fk_alert_assigned_to_app_user")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["incident_case.case_id"], name=op.f("fk_alert_case_id_incident_case")
        ),
        sa.ForeignKeyConstraint(
            ["related_alert_id"], ["alert.alert_id"], name=op.f("fk_alert_related_alert_id_alert")
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["correlation_rule.rule_id"],
            name=op.f("fk_alert_rule_id_correlation_rule"),
        ),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("pk_alert")),
    )
    op.create_index(
        op.f("ix_alert_primary_entity_type_primary_entity_value"),
        "alert",
        ["primary_entity_type", "primary_entity_value"],
        unique=False,
    )
    op.create_index(
        "ix_alert_status_risk",
        "alert",
        ["status", sa.literal_column("risk_score DESC")],
        unique=False,
    )
    op.create_index(
        "uq_alert_open_dedup_key",
        "alert",
        ["dedup_key"],
        unique=True,
        postgresql_where=sa.text("status IN ('new', 'acknowledged', 'in_review')"),
    )
    op.create_table(
        "case_timeline_entry",
        sa.Column("entry_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("entry_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entry_type", sa.Text(), nullable=False),
        sa.Column("author_id", sa.UUID(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "ref",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "entry_type IN ('note', 'status_change', 'alert_linked', 'evidence')",
            name=op.f("ck_case_timeline_entry_entry_type"),
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["app_user.user_id"],
            name=op.f("fk_case_timeline_entry_author_id_app_user"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["incident_case.case_id"],
            name=op.f("fk_case_timeline_entry_case_id_incident_case"),
        ),
        sa.PrimaryKeyConstraint("entry_id", name=op.f("pk_case_timeline_entry")),
    )
    op.create_index(
        op.f("ix_case_timeline_entry_case_id_entry_time"),
        "case_timeline_entry",
        ["case_id", "entry_time"],
        unique=False,
    )
    op.create_table(
        "ti_feed_run",
        sa.Column("feed_run_id", sa.UUID(), nullable=False),
        sa.Column("feed_id", sa.UUID(), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("source_description", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("indicators_received", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("indicators_created", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("indicators_updated", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("indicators_rejected", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "report",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["feed_id"], ["ti_feed.feed_id"], name=op.f("fk_ti_feed_run_feed_id_ti_feed")
        ),
        sa.ForeignKeyConstraint(["job_id"], ["job.job_id"], name=op.f("fk_ti_feed_run_job_id_job")),
        sa.PrimaryKeyConstraint("feed_run_id", name=op.f("pk_ti_feed_run")),
    )
    op.create_table(
        "alert_evidence",
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column("evidence_type", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.BigInteger(), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("step_id", sa.Text(), nullable=True),
        sa.Column(
            "contribution",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "added_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "evidence_type IN ('event', 'classification_result', 'anomaly_result', 'indicator_match')",
            name=op.f("ck_alert_evidence_evidence_type"),
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alert.alert_id"], name=op.f("fk_alert_evidence_alert_id_alert")
        ),
        sa.PrimaryKeyConstraint(
            "alert_id", "evidence_type", "evidence_ref", name=op.f("pk_alert_evidence")
        ),
    )
    op.create_table(
        "case_alert",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column(
            "linked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alert.alert_id"], name=op.f("fk_case_alert_alert_id_alert")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["incident_case.case_id"], name=op.f("fk_case_alert_case_id_incident_case")
        ),
        sa.PrimaryKeyConstraint("case_id", "alert_id", name=op.f("pk_case_alert")),
    )
    op.create_table(
        "ti_indicator",
        sa.Column("indicator_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("feed_id", sa.UUID(), nullable=False),
        sa.Column("indicator_type", sa.Text(), nullable=False),
        sa.Column("value_raw", sa.Text(), nullable=False),
        sa.Column("value_normalized", sa.Text(), nullable=False),
        sa.Column("confidence", sa.SmallInteger(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("tlp", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("stix_id", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "technique_ids",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("last_feed_run_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email')",
            name=op.f("ck_ti_indicator_indicator_type"),
        ),
        sa.CheckConstraint("confidence BETWEEN 0 AND 100", name=op.f("ck_ti_indicator_confidence")),
        sa.ForeignKeyConstraint(
            ["feed_id"], ["ti_feed.feed_id"], name=op.f("fk_ti_indicator_feed_id_ti_feed")
        ),
        sa.ForeignKeyConstraint(
            ["last_feed_run_id"],
            ["ti_feed_run.feed_run_id"],
            name=op.f("fk_ti_indicator_last_feed_run_id_ti_feed_run"),
        ),
        sa.PrimaryKeyConstraint("indicator_id", name=op.f("pk_ti_indicator")),
        sa.UniqueConstraint(
            "feed_id",
            "indicator_type",
            "value_normalized",
            name=op.f("uq_ti_indicator_feed_id_indicator_type_value_normalized"),
        ),
    )
    op.create_index(
        op.f("ix_ti_indicator_indicator_type_value_normalized"),
        "ti_indicator",
        ["indicator_type", "value_normalized"],
        unique=False,
    )
    op.create_table(
        "ti_indicator_version",
        sa.Column("version_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("indicator_id", sa.BigInteger(), nullable=False),
        sa.Column("version_no", sa.Integer(), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("feed_run_id", sa.UUID(), nullable=True),
        sa.ForeignKeyConstraint(
            ["feed_run_id"],
            ["ti_feed_run.feed_run_id"],
            name=op.f("fk_ti_indicator_version_feed_run_id_ti_feed_run"),
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["ti_indicator.indicator_id"],
            name=op.f("fk_ti_indicator_version_indicator_id_ti_indicator"),
        ),
        sa.PrimaryKeyConstraint("version_id", name=op.f("pk_ti_indicator_version")),
        sa.UniqueConstraint(
            "indicator_id",
            "version_no",
            name=op.f("uq_ti_indicator_version_indicator_id_version_no"),
        ),
    )
    op.create_table(
        "indicator_match",
        sa.Column("match_id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("indicator_id", sa.BigInteger(), nullable=False),
        sa.Column("matched_field", sa.Text(), nullable=False),
        sa.Column("matched_value", sa.Text(), nullable=False),
        sa.Column("match_type", sa.Text(), server_default=sa.text("'exact'"), nullable=False),
        sa.Column("indicator_confidence_at_match", sa.SmallInteger(), nullable=False),
        sa.Column("indicator_state_at_match", sa.Text(), nullable=False),
        sa.Column("matcher_version", sa.Text(), nullable=False),
        sa.Column(
            "matched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.CheckConstraint(
            "indicator_state_at_match IN ('active', 'expired', 'revoked')",
            name=op.f("ck_indicator_match_state"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id", "event_time"],
            ["fact_security_event.event_id", "fact_security_event.event_time"],
            name=op.f("fk_indicator_match_event_id_fact_security_event"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["ti_indicator.indicator_id"],
            name=op.f("fk_indicator_match_indicator_id_ti_indicator"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["job.job_id"], name=op.f("fk_indicator_match_job_id_job")
        ),
        sa.PrimaryKeyConstraint("match_id", name=op.f("pk_indicator_match")),
        sa.UniqueConstraint(
            "event_id",
            "event_time",
            "indicator_id",
            "matched_field",
            name=op.f("uq_indicator_match_event_id_event_time_indicator_id_matched_field"),
        ),
    )
    op.create_index(
        op.f("ix_indicator_match_event_id_event_time"),
        "indicator_match",
        ["event_id", "event_time"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicator_match_indicator_id"), "indicator_match", ["indicator_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_indicator_match_indicator_id"), table_name="indicator_match")
    op.drop_index(op.f("ix_indicator_match_event_id_event_time"), table_name="indicator_match")
    op.drop_table("indicator_match")
    op.drop_table("ti_indicator_version")
    op.drop_index(
        op.f("ix_ti_indicator_indicator_type_value_normalized"), table_name="ti_indicator"
    )
    op.drop_table("ti_indicator")
    op.drop_table("case_alert")
    op.drop_table("alert_evidence")
    op.drop_table("ti_feed_run")
    op.drop_index(
        op.f("ix_case_timeline_entry_case_id_entry_time"), table_name="case_timeline_entry"
    )
    op.drop_table("case_timeline_entry")
    op.drop_index(
        "uq_alert_open_dedup_key",
        table_name="alert",
        postgresql_where=sa.text("status IN ('new', 'acknowledged', 'in_review')"),
    )
    op.drop_index("ix_alert_status_risk", table_name="alert")
    op.drop_index(op.f("ix_alert_primary_entity_type_primary_entity_value"), table_name="alert")
    op.drop_table("alert")
    op.drop_table("incident_case")
    op.drop_table("correlation_rule")
    op.drop_table("attack_category_technique")
    op.drop_index(op.f("ix_analyst_feedback_target_type_target_id"), table_name="analyst_feedback")
    op.drop_table("analyst_feedback")
    op.drop_table("ti_feed")
    op.drop_table("attack_technique")
