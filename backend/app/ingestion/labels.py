"""Versioned dataset-label mappings (ML_CLASSIFICATION.md §3)."""

from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.config import REPO_ROOT

LABEL_MAPPING_DIR = REPO_ROOT / "config" / "label_mappings"
_NON_ALNUM = re.compile(r"[^0-9a-z]+")


def normalize_label(label: str) -> str:
    """NFKC -> lowercase -> runs of non-alphanumerics become one space -> trim.

    Makes ``Web Attack <en dash> XSS`` and mis-decoded dash variants map identically."""
    text = unicodedata.normalize("NFKC", label).lower()
    return _NON_ALNUM.sub(" ", text).strip()


@dataclass(frozen=True)
class LabelMapping:
    name: str
    version: int
    entries: dict[str, str]  # normalised raw label -> canonical category code

    @property
    def version_tag(self) -> str:
        return f"{self.name}@{self.version}"

    def map(self, label_raw: str, is_attack: bool | None) -> tuple[str | None, str]:
        """Returns (category code or None, mapping_status)."""
        code = self.entries.get(normalize_label(label_raw))
        if code is None:
            return None, "unmapped"
        if is_attack is not None and (code == "BENIGN") == is_attack:
            return None, "ambiguous"  # dataset's binary label contradicts its category
        return code, "mapped"


@lru_cache
def load_mapping(name: str, directory: Path = LABEL_MAPPING_DIR) -> LabelMapping:
    with (directory / f"{name}.toml").open("rb") as fh:
        data = tomllib.load(fh)
    entries = {normalize_label(str(k)): str(v) for k, v in data["map"].items()}
    return LabelMapping(name=name, version=int(data["version"]), entries=entries)
