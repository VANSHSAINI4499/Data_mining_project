"""Model artifact persistence with integrity checks (ML_CLASSIFICATION.md §10, SECURITY §9).

joblib uses pickle, which can execute code when loading. Therefore artifacts are loaded only
from ``CTI_ARTIFACT_DIR``, only when their SHA-256 equals the value recorded in the registry,
and only under the same scikit-learn major.minor version they were written with. There is no
code path that loads an artifact supplied by a user.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any

import joblib
import numpy
import pandas
import sklearn

from app.core.config import REPO_ROOT

MODEL_FILE = "model.joblib"
MANIFEST_FILE = "manifest.json"
REPORT_FILE = "report.json"


class ArtifactError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def environment() -> dict[str, Any]:
    commit = None
    try:
        commit = (
            subprocess.run(
                ["git", "rev-parse", "HEAD"],  # noqa: S607 - fixed argv, no user input
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout.strip()
            or None
        )
    except (OSError, subprocess.SubprocessError):
        commit = None
    return {
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
        "numpy": numpy.__version__,
        "pandas": pandas.__version__,
        "joblib": joblib.__version__,
        "git_commit": commit,
    }


def _major_minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save(
    artifact_root: Path,
    name: str,
    version: int,
    model: Any,
    manifest: dict[str, Any],
    report: dict[str, Any],
) -> tuple[Path, str]:
    """Write-once: refuses to overwrite an existing version directory."""
    directory = artifact_root / "models" / name / str(version)
    directory.mkdir(parents=True, exist_ok=False)
    model_path = directory / MODEL_FILE
    joblib.dump(model, model_path, compress=3)
    sha = _sha256(model_path)
    (directory / MANIFEST_FILE).write_text(
        json.dumps({**manifest, "artifact_sha256": sha}, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    (directory / REPORT_FILE).write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8"
    )
    return model_path, sha


def load(
    artifact_root: Path, artifact_path: str, expected_sha256: str
) -> tuple[Any, dict[str, Any]]:
    root = artifact_root.resolve()
    path = Path(artifact_path).resolve()
    if not path.is_relative_to(root):
        raise ArtifactError("ARTIFACT_PATH_REJECTED", "artifact is outside the artifact directory")
    if not path.is_file():
        raise ArtifactError("ARTIFACT_NOT_FOUND", f"missing artifact {path.name}")
    if _sha256(path) != expected_sha256:
        raise ArtifactError(
            "ARTIFACT_INTEGRITY_FAILED", "artifact hash does not match the registry"
        )
    manifest = json.loads((path.parent / MANIFEST_FILE).read_text(encoding="utf-8"))
    built_with = manifest.get("environment", {}).get("scikit_learn", "")
    if _major_minor(built_with) != _major_minor(sklearn.__version__):
        raise ArtifactError(
            "ARTIFACT_VERSION_MISMATCH",
            f"built with scikit-learn {built_with}, running {sklearn.__version__}; retrain",
        )
    return joblib.load(path), manifest


def orphan_directories(artifact_root: Path, registered_paths: set[str]) -> list[Path]:
    models = artifact_root / "models"
    if not models.is_dir():
        return []
    registered = {str(Path(p).resolve().parent) for p in registered_paths}
    return [d for d in models.glob("*/*") if d.is_dir() and str(d.resolve()) not in registered]
