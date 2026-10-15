"""Web-attack classification of individual HTTP parameter values (HTTPParamsDataset).

Scope: the input is ONE parameter value (e.g. a query-string or form value), not a full HTTP
request, a session, or an access log. The model predicts whether that value resembles benign
input or one of the injection payload families present in the training data. It does not see
URLs, headers, methods, status codes, or timing, and it never decides to block anything.

Leakage control: rows are grouped by a template signature (lower-case, digit runs -> "0",
whitespace collapsed) so generated variants of one payload template stay in one split. Pure
numeric benign values are grouped by their exact value, because they are independent inputs
rather than templates. All text features are fitted on the training split only.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from app.ml.classification.training import (
    TrainingError,
    _sgkf_first_fold,
    bootstrap_macro_f1,
    evaluate,
)

FEATURE_SET = "http_param_char_tfidf_v1"
LABEL_MAPPING_VERSION = "httpparams@1"
# Dataset attack_type -> canonical class name. Unknown values are rejected, never guessed.
LABEL_MAP = {
    "norm": "BENIGN",
    "sqli": "SQLI",
    "xss": "XSS",
    "path-traversal": "PATH_TRAVERSAL",
    "cmdi": "CMDI",
}
CLASS_DESCRIPTIONS = {
    "BENIGN": "ordinary parameter value (names, addresses, numbers, e-mails, ...)",
    "SQLI": "SQL injection payload",
    "XSS": "cross-site scripting payload",
    "PATH_TRAVERSAL": "path traversal / file inclusion payload",
    "CMDI": "OS command injection payload",
}
MAX_PAYLOAD_CHARS = 8192
REQUIRED_COLUMNS = ("payload", "length", "attack_type", "label")


@dataclass
class LoadReport:
    rows_read: int = 0
    rows_used: int = 0
    excluded: dict[str, int] = field(default_factory=dict)
    file_sha256: str = ""
    raw_label_counts: dict[str, int] = field(default_factory=dict)


def _exclude(report: LoadReport, reason: str) -> None:
    report.excluded[reason] = report.excluded.get(reason, 0) + 1


def load_csv(path: Path) -> tuple[list[str], list[str], LoadReport]:
    """Read a HTTPParamsDataset CSV. Rows whose declared ``length`` differs from the actual
    payload length are malformed (CSV quoting broke and the next record was glued into the
    payload, including its label text) and are excluded."""
    data = path.read_bytes()
    report = LoadReport(file_sha256=hashlib.sha256(data).hexdigest())
    reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
    if reader.fieldnames is None or not set(REQUIRED_COLUMNS) <= set(reader.fieldnames):
        raise TrainingError(f"{path.name}: expected columns {REQUIRED_COLUMNS}")
    texts: list[str] = []
    labels: list[str] = []
    for row in reader:
        report.rows_read += 1
        payload, raw = row["payload"], row["attack_type"]
        report.raw_label_counts[raw] = report.raw_label_counts.get(raw, 0) + 1
        if raw not in LABEL_MAP:
            _exclude(report, f"unknown_label:{raw}")
            continue
        if not row["length"].isdigit() or int(row["length"]) != len(payload):
            _exclude(report, "declared_length_mismatch")
            continue
        if not payload:
            _exclude(report, "empty_payload")
            continue
        if len(payload) > MAX_PAYLOAD_CHARS:
            _exclude(report, "too_long")
            continue
        texts.append(payload)
        labels.append(LABEL_MAP[raw])
    report.rows_used = len(texts)
    return texts, labels, report


_DIGITS = re.compile(r"\d+")
_SPACE = re.compile(r"\s+")


def signature(payload: str) -> str:
    sig = _SPACE.sub(" ", _DIGITS.sub("0", payload.lower())).strip()
    if re.fullmatch(r"[0 ]*", sig):
        return "exact:" + payload  # independent numeric value, not a template
    return sig


def build_vectorizer() -> TfidfVectorizer:
    # Character n-grams capture payload syntax (quotes, comment markers, tags, ../) without a
    # hand-written tokenizer. Lower-casing makes keyword case variations (SeLeCt) equivalent.
    return TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(1, 4),
        lowercase=True,
        min_df=2,
        max_features=100_000,
        sublinear_tf=True,
        dtype=np.float32,
    )


def candidate_models(seed: int) -> dict[str, Any]:
    return {
        "logistic_regression": LogisticRegression(
            C=4.0, class_weight="balanced", max_iter=2000, random_state=seed
        ),
        "linear_svm": LinearSVC(C=0.5, class_weight="balanced", random_state=seed),
    }


def _pipeline(estimator: Any) -> Pipeline:
    return Pipeline([("tfidf", build_vectorizer()), ("model", estimator)])


@dataclass
class TrainOutput:
    pipeline: Pipeline
    metrics: dict[str, Any]
    split_report: dict[str, Any]
    timings: dict[str, float]
    labels: list[str]


def train(texts: list[str], labels: list[str], seed: int = 42) -> TrainOutput:
    if len(texts) != len(labels) or not texts:
        raise TrainingError("no training data")
    y = np.asarray(labels)
    x = np.asarray(texts, dtype=object)
    groups = np.asarray([signature(t) for t in texts])
    class_labels = sorted(set(labels), key=lambda c: (c != "BENIGN", c))

    t0 = time.perf_counter()
    rest, test = _sgkf_first_fold(y, groups, 0.2, seed)
    tr, va = _sgkf_first_fold(y[rest], groups[rest], 0.2, seed + 1)
    train_idx, val_idx = np.sort(rest[tr]), np.sort(rest[va])
    test_idx = np.sort(test)
    overlap = len(set(groups[train_idx]) & (set(groups[val_idx]) | set(groups[test_idx]))) + len(
        set(groups[val_idx]) & set(groups[test_idx])
    )
    if overlap:
        raise TrainingError(f"{overlap} template groups appear in more than one split")

    def counts(idx: np.ndarray) -> dict[str, int]:
        u, c = np.unique(y[idx], return_counts=True)
        return {str(k): int(v) for k, v in zip(u, c, strict=True)}

    split_report = {
        "strategy": "group_stratified",
        "group_key": "template_signature",
        "groups": len(set(groups)),
        "cross_split_groups": 0,
        "train_rows": len(train_idx),
        "validation_rows": len(val_idx),
        "test_rows": len(test_idx),
        "train_class_counts": counts(train_idx),
        "validation_class_counts": counts(val_idx),
        "test_class_counts": counts(test_idx),
        "classes_missing_from_test": sorted(set(y[train_idx]) - set(y[test_idx])),
    }
    timings = {"split_seconds": time.perf_counter() - t0}

    models: dict[str, Any] = {}
    fitted: dict[str, Pipeline] = {}
    t0 = time.perf_counter()
    dummy = DummyClassifier(strategy="stratified", random_state=seed)
    dummy.fit(np.zeros((len(train_idx), 1)), y[train_idx])
    for name, est in candidate_models(seed).items():
        pipe = _pipeline(est)
        pipe.fit(x[train_idx], y[train_idx])
        fitted[name] = pipe
    timings["training_seconds"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    val_scores = {}
    for name, pipe in fitted.items():
        val_pred = pipe.predict(x[val_idx])
        models[name] = {"validation": evaluate(y[val_idx], val_pred, class_labels)}
        val_scores[name] = models[name]["validation"]["macro_f1"]
    models["dummy_stratified"] = {
        "validation": evaluate(y[val_idx], dummy.predict(np.zeros((len(val_idx), 1))), class_labels)
    }
    primary = max(val_scores, key=lambda n: (val_scores[n], n == "logistic_regression"))
    timings["validation_seconds"] = time.perf_counter() - t0

    # The test split is used once, after model selection, for every model (for comparison).
    t0 = time.perf_counter()
    for name, pipe in fitted.items():
        models[name]["test"] = evaluate(y[test_idx], pipe.predict(x[test_idx]), class_labels)
    models["dummy_stratified"]["test"] = evaluate(
        y[test_idx], dummy.predict(np.zeros((len(test_idx), 1))), class_labels
    )
    test_pred = fitted[primary].predict(x[test_idx])
    ci = bootstrap_macro_f1(y[test_idx], test_pred, class_labels, 1000, seed)
    timings["evaluation_seconds"] = time.perf_counter() - t0

    errors = _error_counts(y[test_idx], test_pred)
    metrics = {
        "models": models,
        "primary_model": primary,
        "selection_metric": "validation macro-F1",
        "class_labels": class_labels,
        "test_macro_f1_ci": ci,
        "test_errors": errors,
        "split": split_report,
        "vocabulary_size": len(fitted[primary].named_steps["tfidf"].vocabulary_),
    }
    return TrainOutput(fitted[primary], metrics, split_report, timings, class_labels)


def _error_counts(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    malicious_true, malicious_pred = y_true != "BENIGN", y_pred != "BENIGN"
    per_class = {}
    for label in sorted(set(y_true) | set(y_pred)):
        per_class[label] = {
            "false_positives": int(((y_pred == label) & (y_true != label)).sum()),
            "false_negatives": int(((y_true == label) & (y_pred != label)).sum()),
        }
    return {
        "binary_false_positives": int((malicious_pred & ~malicious_true).sum()),
        "binary_false_negatives": int((~malicious_pred & malicious_true).sum()),
        "attack_class_confusions": int(
            (malicious_true & malicious_pred & (y_true != y_pred)).sum()
        ),
        "per_class": per_class,
    }


def evaluate_lexical(pipeline: Pipeline, path: Path) -> dict[str, Any]:
    """Out-of-distribution check on payload_test_lexical.csv: benign forum sentences vs SQL/JS
    *code* (not attack payloads). Only the attack/benign decision is meaningful here."""
    data = path.read_bytes().decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(data)))
    texts = [r["payload"][:MAX_PAYLOAD_CHARS] for r in rows]
    truth = np.asarray([r["label"] != "norm" for r in rows])
    pred = pipeline.predict(np.asarray(texts, dtype=object)) != "BENIGN"
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    return {
        "rows": len(rows),
        "truncated_to_chars": MAX_PAYLOAD_CHARS,
        "code_samples": int(truth.sum()),
        "benign_samples": int((~truth).sum()),
        "flagged_code_samples": tp,
        "flagged_benign_samples": fp,
        "missed_code_samples": fn,
        "benign_false_positive_rate": round(fp / max(1, int((~truth).sum())), 4),
        "code_detection_rate": round(tp / max(1, int(truth.sum())), 4),
        "note": "lexical set contains SQL/JS source code, not injection payloads; reported as "
        "an out-of-distribution sanity check only",
    }


def predict(pipeline: Pipeline, payloads: list[str]) -> list[dict[str, Any]]:
    """Classify parameter values. Scores are uncalibrated decision scores, not probabilities."""
    if not payloads:
        return []
    clean = [p if isinstance(p, str) else "" for p in payloads]
    x = np.asarray([p[:MAX_PAYLOAD_CHARS] for p in clean], dtype=object)
    labels = list(pipeline.classes_)
    predicted = pipeline.predict(x)
    model = pipeline.named_steps["model"]
    if hasattr(model, "predict_proba"):
        raw = pipeline.predict_proba(x)
        kind = "logistic_regression_probability_uncalibrated"
    else:
        raw = pipeline.decision_function(x)
        kind = "svm_decision_score"
    out = []
    for i, payload in enumerate(clean):
        scores = {labels[j]: round(float(raw[i][j]), 6) for j in range(len(labels))}
        out.append(
            {
                "index": i,
                "predicted_class": str(predicted[i]),
                "is_attack_like": str(predicted[i]) != "BENIGN",
                "score": scores[str(predicted[i])],
                "class_scores": scores,
                "score_kind": kind,
                "empty_input": payload == "",
                "truncated": len(payload) > MAX_PAYLOAD_CHARS,
            }
        )
    return out
