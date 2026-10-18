"""Database role separation (SECURITY_REQUIREMENTS.md §6, DEPLOYMENT_GUIDE.md).

The schema owner (migration role) runs Alembic and ``cti db grant-app-role``; the application
connects as a separate, DML-only role:

- SELECT/INSERT/UPDATE/DELETE on application tables, USAGE/SELECT on sequences;
- no CREATE on the schema (no DDL), not a superuser, does not own anything;
- no UPDATE/DELETE/TRUNCATE on ``audit_log`` (pruning goes through ``prune_audit_log``);
- read-only on ``alembic_version`` (readiness checks the schema revision);
- EXECUTE on the two SECURITY DEFINER functions (partition creation, audit pruning).

Default privileges make tables created by later migrations available to the role, except
that ``audit_log``-style restrictions must be re-applied by re-running the command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg import sql

ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
DEFINER_FUNCTIONS = (
    "ensure_event_partitions(timestamptz, timestamptz)",
    "prune_audit_log(timestamptz)",
)
READ_ONLY_TABLES = ("alembic_version",)
APPEND_ONLY_TABLES = ("audit_log",)


class RoleSetupError(Exception):
    pass


@dataclass
class PrivilegeReport:
    role: str
    owner: str
    problems: list[str] = field(default_factory=list)
    checks: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "owner": self.owner,
            "ok": not self.problems,
            "problems": self.problems,
            "checks": self.checks,
        }


def grant_statements(role: str, database: str) -> list[sql.Composed]:
    """Idempotent statements run by the schema owner for the application role."""
    r = sql.Identifier(role)
    stmts = [
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(database), r),
        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(r),
        sql.SQL("REVOKE CREATE ON SCHEMA public FROM {}").format(r),
        sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(
            r
        ),
        sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(r),
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
        ).format(r),
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}"
        ).format(r),
    ]
    for table in APPEND_ONLY_TABLES:
        stmts.append(
            sql.SQL("REVOKE UPDATE, DELETE, TRUNCATE ON {} FROM {}").format(
                sql.Identifier(table), r
            )
        )
    for table in READ_ONLY_TABLES:
        stmts.append(
            sql.SQL("REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON {} FROM {}").format(
                sql.Identifier(table), r
            )
        )
    for fn in DEFINER_FUNCTIONS:
        # Function signatures are fixed constants above, never user input.
        stmts.append(sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(sql.SQL(fn), r))
    return stmts


def _libpq_url(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def grant_app_role(owner_url: str, role: str) -> PrivilegeReport:
    """Apply the grants as the schema owner, then verify them. Raises RoleSetupError."""
    if not ROLE_NAME.match(role):
        raise RoleSetupError(f"invalid role name {role!r} (lower-case letters, digits, _)")
    with psycopg.connect(_libpq_url(owner_url)) as conn:
        owner, database = conn.execute("SELECT current_user, current_database()").fetchone() or (
            None,
            None,
        )
        found = conn.execute(
            "SELECT rolsuper, rolcanlogin FROM pg_roles WHERE rolname = %s", (role,)
        ).fetchone()
        if found is None:
            raise RoleSetupError(
                f"role {role!r} does not exist; create it first (see DEPLOYMENT_GUIDE.md)"
            )
        if role == owner:
            raise RoleSetupError(
                "the application role must differ from the schema owner used for migrations"
            )
        if found[0]:
            raise RoleSetupError(f"role {role!r} is a superuser; use a non-superuser role")
        with conn.transaction():
            for stmt in grant_statements(role, str(database)):
                conn.execute(stmt)
        return privilege_report(conn, role, str(owner))


def privilege_report(conn: psycopg.Connection[Any], role: str, owner: str) -> PrivilegeReport:
    report = PrivilegeReport(role=role, owner=owner)
    row = conn.execute(
        "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
        "FROM pg_roles WHERE rolname = %s",
        (role,),
    ).fetchone()
    if row is None:
        report.problems.append("role does not exist")
        return report
    report.checks["attributes"] = dict(
        zip(("superuser", "createrole", "createdb", "bypassrls"), row, strict=True)
    )
    if row[0]:
        report.problems.append("role is a superuser")
    schema_create = conn.execute(
        "SELECT has_schema_privilege(%s, 'public', 'CREATE')", (role,)
    ).fetchone()
    report.checks["schema_create"] = bool(schema_create and schema_create[0])
    if report.checks["schema_create"]:
        report.problems.append("role can CREATE in schema public (DDL)")
    owned = conn.execute(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) = %s",
        (role,),
    ).fetchone()
    report.checks["owned_relations"] = int(owned[0]) if owned else 0
    if report.checks["owned_relations"]:
        report.problems.append("role owns relations in schema public")
    missing = [
        t
        for (t,) in conn.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition "
            "AND c.relname <> ALL(%s) AND NOT ("
            "has_table_privilege(%s, c.oid, 'SELECT') AND has_table_privilege(%s, c.oid, 'INSERT')"
            " AND has_table_privilege(%s, c.oid, 'UPDATE')"
            " AND has_table_privilege(%s, c.oid, 'DELETE'))",
            (list(APPEND_ONLY_TABLES + READ_ONLY_TABLES), role, role, role, role),
        )
    ]
    report.checks["tables_missing_dml"] = missing
    if missing:
        report.problems.append(f"missing DML on {len(missing)} table(s)")
    for table in APPEND_ONLY_TABLES:
        for priv in ("INSERT", "SELECT", "UPDATE", "DELETE", "TRUNCATE"):
            got = conn.execute(
                "SELECT has_table_privilege(%s, %s, %s)", (role, table, priv)
            ).fetchone()
            allowed = bool(got and got[0])
            report.checks[f"{table}.{priv.lower()}"] = allowed
            if allowed != (priv in ("INSERT", "SELECT")):
                report.problems.append(f"{table}: {priv} is {'granted' if allowed else 'missing'}")
    for table in READ_ONLY_TABLES:
        got = conn.execute(
            "SELECT has_table_privilege(%s, %s, 'SELECT'), has_table_privilege(%s, %s, 'UPDATE')",
            (role, table, role, table),
        ).fetchone()
        report.checks[f"{table}.select"], report.checks[f"{table}.update"] = (
            bool(got and got[0]),
            bool(got and got[1]),
        )
        if not report.checks[f"{table}.select"] or report.checks[f"{table}.update"]:
            report.problems.append(f"{table}: expected read-only access")
    for fn in DEFINER_FUNCTIONS:
        got = conn.execute(
            "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (role, fn)
        ).fetchone()
        report.checks[f"execute {fn}"] = bool(got and got[0])
        if not report.checks[f"execute {fn}"]:
            report.problems.append(f"cannot execute {fn}")
    return report
