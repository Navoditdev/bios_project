"""Train and evaluate the synthetic XGBoost payer-behavior classifier."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import xgboost as xgb

from behavior_risk import FEATURE_NAMES
from synthetic_behavior_data import generate_rows


def grouped_splits(rows: list[dict[str, Any]], seed: int) -> dict[str, set[str]]:
    """Split complete sessions to avoid temporal/session leakage across sets."""
    sessions = sorted({row["session_id"] for row in rows})
    random.Random(seed).shuffle(sessions)
    n = len(sessions)
    n_train = int(n * 0.70)
    n_validation = int(n * 0.15)
    n_calibration = int(n * 0.10)
    return {
        "train": set(sessions[:n_train]),
        "validation": set(sessions[n_train:n_train + n_validation]),
        "calibration": set(sessions[n_train + n_validation:n_train + n_validation + n_calibration]),
        "test": set(sessions[n_train + n_validation + n_calibration:]),
    }


def choose_threshold(
    labels: np.ndarray,
    scores: np.ndarray,
    max_false_positive_rate: float = 0.01,
) -> float:
    """Maximize recall on calibration data within a small benign false-positive rate."""
    negatives = labels == 0
    positives = labels == 1
    if not np.any(negatives) or not np.any(positives):
        raise ValueError("Calibration split must contain both benign and attack rows.")
    candidates = np.unique(scores)
    eligible: list[tuple[float, float]] = []
    for threshold in candidates:
        false_positive_rate = float(np.mean(scores[negatives] >= threshold))
        recall = float(np.mean(scores[positives] >= threshold))
        if false_positive_rate <= max_false_positive_rate:
            eligible.append((recall, float(threshold)))
    if not eligible:
        return float(np.nextafter(float(np.max(scores)), math.inf))
    best_recall = max(recall for recall, _ in eligible)
    # On ties, use the higher threshold to reduce benign blocks.
    return max(threshold for recall, threshold in eligible if recall == best_recall)


def rates(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    predicted = scores >= threshold
    positives = labels == 1
    negatives = labels == 0
    tp = int(np.sum(predicted & positives))
    fp = int(np.sum(predicted & negatives))
    fn = int(np.sum(~predicted & positives))
    return {
        "precision": tp / max(tp + fp, 1),
        "recall": tp / max(tp + fn, 1),
        "false_positive_rate": fp / max(int(np.sum(negatives)), 1),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
    }


def write_dataset(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = ["session_id", "session_kind", "event_index", *FEATURE_NAMES, "label"]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def train(
    sessions_per_kind: int = 400,
    seed: int = 42,
    model_dir: Path | None = None,
    dataset_path: Path | None = None,
) -> dict[str, Any]:
    model_dir = model_dir or Path(__file__).with_name("models")
    dataset_path = dataset_path or Path(__file__).with_name("data") / "synthetic_behavior_training.csv"
    rows = generate_rows(sessions_per_kind=sessions_per_kind, seed=seed)
    write_dataset(dataset_path, rows)
    splits = grouped_splits(rows, seed)

    def matrix(split: str) -> tuple[np.ndarray, np.ndarray]:
        selected = [row for row in rows if row["session_id"] in splits[split]]
        X = np.asarray([[row[name] for name in FEATURE_NAMES] for row in selected], dtype=np.float32)
        y = np.asarray([row["label"] for row in selected], dtype=np.int32)
        if not len(y) or len(np.unique(y)) != 2:
            raise ValueError(f"The {split} split must contain both labels.")
        return X, y

    X_train, y_train = matrix("train")
    X_validation, y_validation = matrix("validation")
    X_calibration, y_calibration = matrix("calibration")
    X_test, y_test = matrix("test")

    dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=list(FEATURE_NAMES))
    dvalidation = xgb.DMatrix(
        X_validation, label=y_validation, feature_names=list(FEATURE_NAMES)
    )
    model = xgb.train(
        {
            "objective": "binary:logistic",
            "tree_method": "hist",
            "eval_metric": "aucpr",
            "eta": 0.05,
            "max_depth": 4,
            "min_child_weight": 5,
            "subsample": 0.85,
            "colsample_bytree": 0.9,
            "lambda": 5.0,
            "nthread": 2,
            "seed": seed,
        },
        dtrain,
        num_boost_round=700,
        evals=[(dvalidation, "validation")],
        callbacks=[xgb.callback.EarlyStopping(rounds=40, save_best=True)],
        verbose_eval=False,
    )
    calibration_scores = model.predict(
        xgb.DMatrix(X_calibration, feature_names=list(FEATURE_NAMES))
    )
    threshold = choose_threshold(y_calibration, calibration_scores)
    test_scores = model.predict(xgb.DMatrix(X_test, feature_names=list(FEATURE_NAMES)))
    test_metrics = rates(y_test, test_scores, threshold)

    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "payment_risk.ubj"
    metadata_path = model_dir / "payment_risk.json"
    model.save_model(str(model_path))
    metadata = {
        "model_type": "XGBoost binary classifier",
        "xgboost_version": xgb.__version__,
        "feature_schema_version": 1,
        "feature_names": list(FEATURE_NAMES),
        "risk_threshold": threshold,
        "best_iteration": int(model.best_iteration),
        "threshold_method": "maximum calibration recall at <=1% synthetic benign false-positive rate",
        "test_metrics": test_metrics,
        "sessions_per_kind": sessions_per_kind,
        "rows": len(rows),
        "seed": seed,
        "training_data": "synthetic only; not a real-world fraud probability",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_file": model_path.name,
        "training_csv": dataset_path.name,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions-per-kind", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-dir", type=Path, default=Path(__file__).with_name("models"))
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).with_name("data") / "synthetic_behavior_training.csv",
    )
    args = parser.parse_args()
    result = train(args.sessions_per_kind, args.seed, args.model_dir, args.dataset)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
