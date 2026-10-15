"""Web payload classifier: loading, labels, grouping, training, inference (no database)."""

from __future__ import annotations

import random
from pathlib import Path

import numpy as np
import pytest

from app.ml import web_payload as wp
from app.ml.classification.training import TrainingError

HEADER = '"payload","length","attack_type","label"\n'


def _row(payload: str, attack_type: str, length: int | None = None) -> str:
    label = "norm" if attack_type == "norm" else "anom"
    quoted = payload.replace('"', '""')
    return f'"{quoted}","{len(payload) if length is None else length}","{attack_type}","{label}"\n'


def synthetic_rows(n_per_class: int = 60, seed: int = 0) -> list[tuple[str, str]]:
    """Small, clearly separable synthetic payloads (not taken from the public dataset)."""
    rng = random.Random(seed)
    words = ["calle", "mayor", "plaza", "luna", "verde", "norte", "rio", "monte", "sol", "mar"]
    rows = []
    for i in range(n_per_class):
        rows.append((f"{rng.choice(words)} {rng.choice(words)} {i}", "norm"))
        rows.append((f"{rng.choice(words)}{i}@example.test", "norm"))
        rows.append((f"{i}' or {i}={i} -- {rng.choice(words)}", "sqli"))
        rows.append((f"1 union select {rng.choice(words)}_{i} from users--", "sqli"))
        rows.append((f"<script>alert('{rng.choice(words)}{i}')</script>", "xss"))
        rows.append((f"{'../' * (2 + i % 5)}etc/{rng.choice(words)}{i}", "path-traversal"))
        rows.append((f"; ping -c {i} {rng.choice(words)}.test", "cmdi"))
    return rows


def write_csv(path: Path, rows: list[tuple[str, str]], extra: str = "") -> Path:
    path.write_text(HEADER + "".join(_row(p, t) for p, t in rows) + extra, encoding="utf-8")
    return path


def test_load_csv_maps_labels_and_excludes_bad_rows(tmp_path: Path) -> None:
    extra = (
        _row("abc", "norm", length=99)  # declared length mismatch (malformed row)
        + _row("weird", "ldap-injection")  # unknown label: rejected, never guessed
        + _row("", "norm")
    )
    path = write_csv(tmp_path / "p.csv", [("hello", "norm"), ("1' or 1=1", "sqli")], extra)
    texts, labels, report = wp.load_csv(path)
    assert texts == ["hello", "1' or 1=1"]
    assert labels == ["BENIGN", "SQLI"]
    assert report.rows_read == 5 and report.rows_used == 2
    assert report.excluded == {
        "declared_length_mismatch": 1,
        "unknown_label:ldap-injection": 1,
        "empty_payload": 1,
    }
    assert len(report.file_sha256) == 64


def test_load_csv_requires_columns(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("text,label\nx,norm\n", encoding="utf-8")
    with pytest.raises(TrainingError, match="expected columns"):
        wp.load_csv(path)


def test_signature_groups_templates_but_not_plain_numbers() -> None:
    assert wp.signature("1' OR 12=12 --") == wp.signature("7' or 3=3   --")
    assert wp.signature("12345") != wp.signature("67890")
    assert wp.signature("12345").startswith("exact:")


def test_label_map_covers_dataset_classes_only() -> None:
    assert set(wp.LABEL_MAP) == {"norm", "sqli", "xss", "path-traversal", "cmdi"}
    assert set(wp.LABEL_MAP.values()) == set(wp.CLASS_DESCRIPTIONS)


@pytest.fixture(scope="module")
def trained() -> wp.TrainOutput:
    rows = synthetic_rows()
    return wp.train([p for p, _ in rows], [wp.LABEL_MAP[t] for _, t in rows], seed=7)


def test_training_split_has_no_shared_groups(trained: wp.TrainOutput) -> None:
    split = trained.split_report
    assert split["cross_split_groups"] == 0
    assert split["train_rows"] + split["validation_rows"] + split["test_rows"] == 420
    assert set(split["test_class_counts"]) == {"BENIGN", "SQLI", "XSS", "PATH_TRAVERSAL", "CMDI"}
    models = trained.metrics["models"]
    assert set(models) == {"logistic_regression", "linear_svm", "dummy_stratified"}
    best = models[trained.metrics["primary_model"]]["test"]["macro_f1"]
    assert best > models["dummy_stratified"]["test"]["macro_f1"]


def test_predict_benign_and_malicious_examples(trained: wp.TrainOutput) -> None:
    results = wp.predict(
        trained.pipeline,
        ["calle verde 4", "9' or 9=9 -- luna", "<script>alert('x')</script>", "../../../etc/x"],
    )
    assert [r["predicted_class"] for r in results] == ["BENIGN", "SQLI", "XSS", "PATH_TRAVERSAL"]
    assert results[0]["is_attack_like"] is False and results[1]["is_attack_like"] is True
    assert set(results[1]["class_scores"]) == set(trained.labels)


def test_predict_handles_empty_missing_and_oversized_input(trained: wp.TrainOutput) -> None:
    assert wp.predict(trained.pipeline, []) == []
    huge = "a" * (wp.MAX_PAYLOAD_CHARS + 10)
    results = wp.predict(trained.pipeline, ["", None, huge])  # type: ignore[list-item]
    assert [r["empty_input"] for r in results] == [True, True, False]
    assert results[2]["truncated"] is True
    assert all(r["predicted_class"] in trained.labels for r in results)


def test_training_is_reproducible() -> None:
    rows = synthetic_rows(n_per_class=40, seed=3)
    texts, labels = [p for p, _ in rows], [wp.LABEL_MAP[t] for _, t in rows]
    a, b = wp.train(texts, labels, seed=11), wp.train(texts, labels, seed=11)
    assert a.split_report == b.split_report
    sample = np.asarray(texts[:50], dtype=object)
    assert (a.pipeline.predict(sample) == b.pipeline.predict(sample)).all()


def test_training_rejects_empty_data() -> None:
    with pytest.raises(TrainingError):
        wp.train([], [])
