"""Online behavior features and XGBoost risk scoring for payer attempts."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import numpy as np


ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = ROOT / "models" / "payment_risk.ubj"
DEFAULT_METADATA_PATH = ROOT / "models" / "payment_risk.json"
DEFAULT_EVENT_DB = ROOT / "data" / "behavior_events.sqlite3"

FEATURE_NAMES = (
    "amount_ratio",
    "amount_valid",
    "over_per_payment_limit",
    "calls_30s",
    "calls_5m",
    "calls_1h",
    "calls_24h",
    "units_5m_hour_budget_ratio",
    "units_1h_hour_budget_ratio",
    "units_24h_day_budget_ratio",
    "near_cap_calls_10m",
    "near_cap_calls_24h",
    "denials_5m",
    "unique_resources_1h",
    "resource_is_new",
    "same_amount_calls_5m",
    "seconds_since_last_call",
)


def resource_origin(resource_url: Any) -> str:
    """Keep only a URL origin for behavior features; do not persist query data."""
    if not isinstance(resource_url, str):
        return "invalid"
    try:
        parsed = urlsplit(resource_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "invalid"
        return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}"
    except ValueError:
        return "invalid"


def build_features(
    *,
    amount: int | None,
    resource: str,
    history: list[dict[str, Any]],
    now: float,
    max_amount: int,
    hourly_budget: int,
    daily_budget: int,
) -> dict[str, float]:
    """Build causal, fixed-window features from this attempt and prior attempts."""
    valid_amount = type(amount) is int and amount > 0
    value = amount if valid_amount else 0
    previous = [event for event in history if now - float(event["created_at"]) < 86400]

    def recent(seconds: int) -> list[dict[str, Any]]:
        return [event for event in previous if now - float(event["created_at"]) < seconds]

    last_30s = recent(30)
    last_5m = recent(300)
    last_1h = recent(3600)
    last_24h = recent(86400)
    denominator_amount = max_amount if max_amount > 0 else 1
    denominator_hour = hourly_budget if hourly_budget > 0 else 1
    denominator_day = daily_budget if daily_budget > 0 else 1
    near_cap = lambda event: int(event.get("amount") or 0) >= 0.9 * denominator_amount
    denials_5m = sum(
        1 for event in last_5m if str(event.get("outcome", "")).startswith("denied")
    )
    origins_1h = {str(event.get("resource", "invalid")) for event in last_1h}
    same_amount = sum(1 for event in last_5m if event.get("amount") == value)
    last_event_time = max(
        (float(event["created_at"]) for event in previous),
        default=now - 86400,
    )

    return {
        "amount_ratio": min(value / denominator_amount, 2.0),
        "amount_valid": float(valid_amount),
        "over_per_payment_limit": float(valid_amount and value > max_amount),
        "calls_30s": float(len(last_30s)),
        "calls_5m": float(len(last_5m)),
        "calls_1h": float(len(last_1h)),
        "calls_24h": float(len(last_24h)),
        "units_5m_hour_budget_ratio": min(
            sum(int(event.get("amount") or 0) for event in last_5m) / denominator_hour, 5.0
        ),
        "units_1h_hour_budget_ratio": min(
            sum(int(event.get("amount") or 0) for event in last_1h) / denominator_hour, 5.0
        ),
        "units_24h_day_budget_ratio": min(
            sum(int(event.get("amount") or 0) for event in last_24h) / denominator_day, 5.0
        ),
        "near_cap_calls_10m": float(sum(near_cap(event) for event in recent(600))),
        "near_cap_calls_24h": float(sum(near_cap(event) for event in last_24h)),
        "denials_5m": float(denials_5m),
        "unique_resources_1h": float(len(origins_1h)),
        "resource_is_new": float(resource not in {event.get("resource") for event in last_24h}),
        "same_amount_calls_5m": float(same_amount),
        "seconds_since_last_call": min(max(now - last_event_time, 0.0), 86400.0),
    }


@dataclass(frozen=True)
class BehaviorAssessment:
    event_id: str
    score: float | None
    threshold: float
    blocked: bool
    detail: str


class BehaviorRiskMonitor:
    """Thread-safe event store and optional XGBoost scoring for one payer."""

    def __init__(
        self,
        model_path: str | Path = DEFAULT_MODEL_PATH,
        metadata_path: str | Path = DEFAULT_METADATA_PATH,
        database_path: str | Path = DEFAULT_EVENT_DB,
        agent_id: str = "local-demo-agent",
        clock=time.time,
    ) -> None:
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.agent_id = agent_id
        self._clock = clock
        self._lock = threading.RLock()
        self._model = None
        self._xgb = None
        self._threshold = 1.1
        self._model_error: str | None = None
        self._load_model()

        db_path = str(database_path)
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS behavior_events (
                event_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                amount INTEGER,
                resource TEXT NOT NULL,
                outcome TEXT NOT NULL
            )"""
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS behavior_events_agent_time "
            "ON behavior_events(agent_id, created_at)"
        )
        self._connection.commit()

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def threshold(self) -> float:
        return self._threshold

    def _load_model(self) -> None:
        if not self.model_path.exists() or not self.metadata_path.exists():
            self._model_error = "Trained model artifact is missing."
            return
        try:
            import xgboost as xgb

            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            if metadata.get("feature_names") != list(FEATURE_NAMES):
                raise ValueError("Model feature schema does not match this code.")
            self._threshold = float(metadata["risk_threshold"])
            model = xgb.Booster()
            model.load_model(str(self.model_path))
            self._model = model
            self._xgb = xgb
        except Exception as error:  # The hard payer rules remain available on model failure.
            self._model_error = f"Could not load trained model: {error}"

    def inspect_attempt(
        self,
        requirements: Any,
        *,
        max_amount: int,
        hourly_budget: int,
        daily_budget: int,
    ) -> tuple[BehaviorAssessment, dict[str, float]]:
        """Score and persist an attempt before payer rules or signing run."""
        amount: int | None = None
        resource_url: Any = None
        if isinstance(requirements, dict):
            resource = requirements.get("resource")
            resource_url = resource.get("url") if isinstance(resource, dict) else None
            accepts = requirements.get("accepts")
            if isinstance(accepts, list) and accepts and isinstance(accepts[0], dict):
                raw_amount = accepts[0].get("amount")
                if isinstance(raw_amount, str) and raw_amount.isdecimal():
                    amount = int(raw_amount)
        origin = resource_origin(resource_url)
        now = self._clock()
        event_id = str(uuid.uuid4())

        with self._lock:
            connection = self._connection
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT created_at, amount, resource, outcome FROM behavior_events "
                    "WHERE agent_id = ? AND created_at > ? ORDER BY created_at",
                    (self.agent_id, now - 86400),
                ).fetchall()
                history = [dict(row) for row in rows]
                features = build_features(
                    amount=amount,
                    resource=origin,
                    history=history,
                    now=now,
                    max_amount=max_amount,
                    hourly_budget=hourly_budget,
                    daily_budget=daily_budget,
                )
                score = None
                blocked = False
                if self._model is not None:
                    vector = np.asarray(
                        [[features[name] for name in FEATURE_NAMES]], dtype=np.float32
                    )
                    matrix = self._xgb.DMatrix(
                        vector, feature_names=list(FEATURE_NAMES)
                    )
                    score = float(self._model.predict(matrix)[0])
                    blocked = score >= self._threshold
                    detail = (
                        f"XGBoost behavioral risk {score:.1%} "
                        f"({'DENY' if blocked else 'below deny threshold'}; "
                        f"threshold {self._threshold:.1%})."
                    )
                else:
                    detail = (
                        f"ML scoring unavailable ({self._model_error or 'unknown error'}); "
                        "deterministic payer limits still apply."
                    )
                connection.execute(
                    "INSERT INTO behavior_events "
                    "(event_id, agent_id, created_at, amount, resource, outcome) "
                    "VALUES (?, ?, ?, ?, ?, 'pending')",
                    (event_id, self.agent_id, now, amount, origin),
                )
                connection.execute(
                    "DELETE FROM behavior_events WHERE agent_id = ? AND created_at < ?",
                    (self.agent_id, now - 7 * 86400),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        return BehaviorAssessment(event_id, score, self._threshold, blocked, detail), features

    def record_outcome(self, event_id: str | None, outcome: str) -> None:
        """Attach the policy or payment outcome to a previously observed attempt."""
        if not event_id:
            return
        with self._lock:
            self._connection.execute(
                "UPDATE behavior_events SET outcome = ? WHERE event_id = ? AND agent_id = ?",
                (outcome[:40], event_id, self.agent_id),
            )
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()
