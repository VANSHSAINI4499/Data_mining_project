"""Import-boundary rules from DEVELOPMENT_RULES.md §3, checked statically with ``ast``."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

APP = Path(__file__).resolve().parents[2] / "app"

# package -> forbidden import prefixes
RULES: dict[str, tuple[str, ...]] = {
    "app.api": ("app.repositories", "app.models", "sqlalchemy"),
    "app.services": ("app.api", "fastapi", "starlette"),
    "app.repositories": ("app.services", "app.api"),
    "app.jobs": ("app.api", "app.repositories", "app.models"),
    "app.core": ("app.api", "app.services", "app.repositories", "app.jobs"),
}


def _module_name(path: Path) -> str:
    rel = path.relative_to(APP.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def _violations() -> list[str]:
    problems = []
    for path in APP.rglob("*.py"):
        module = _module_name(path)
        for package, forbidden in RULES.items():
            if module == package or module.startswith(package + "."):
                for imported in _imports(path):
                    if any(imported == f or imported.startswith(f + ".") for f in forbidden):
                        problems.append(f"{module} imports {imported}")
    return problems


def test_architecture_boundaries() -> None:
    assert _violations() == []


def test_rule_table_covers_existing_packages() -> None:
    packages = {p.name for p in APP.iterdir() if p.is_dir() and (p / "__init__.py").exists()}
    assert {"api", "services", "repositories", "jobs", "core"} <= packages
