"""Generate labeled synthetic payer-behavior sessions for model training."""

from __future__ import annotations

import random
from typing import Any

from behavior_risk import FEATURE_NAMES, build_features


ATTACK_KINDS = (
    "near_cap_burst",
    "small_payment_flood",
    "policy_probe",
    "resource_churn",
    "slow_drain",
)


def _session_events(kind: str, rng: random.Random) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    now = 1_700_000_000.0 + rng.randrange(0, 365 * 86400)
    if kind == "normal":
        count = rng.randint(1, 6)
        amount_pool = [100, 250, 500, 900, 1500, 3000, 6000, 9500, 10000]
        for index in range(count):
            if count <= 3 and rng.random() < 0.3:
                now += rng.randint(2, 25)
            else:
                now += rng.randint(15 * 60, 4 * 3600)
            resource = rng.choice(("https://docs.example", "https://api.example"))
            events.append({
                "created_at": now,
                "amount": rng.choice(amount_pool),
                "resource": resource,
                "outcome": "settled",
                "label": 0,
            })
        return events

    if kind == "near_cap_burst":
        count = rng.randint(3, 7)
        for index in range(count):
            now += rng.randint(1, 18)
            events.append({
                "created_at": now,
                "amount": rng.randint(9000, 9999),
                "resource": "https://api.example",
                "outcome": "settled" if index == 0 else "denied_budget",
                "label": int(index >= 1),
            })
        return events

    if kind == "small_payment_flood":
        count = rng.randint(8, 14)
        amount_max = min(800, 8500 // count)
        for index in range(count):
            now += rng.randint(1, 8)
            events.append({
                "created_at": now,
                "amount": rng.randint(100, amount_max),
                "resource": "https://api.example",
                "outcome": "settled",
                "label": int(index >= 4),
            })
        return events

    if kind == "policy_probe":
        count = rng.randint(5, 11)
        amounts: list[int | None] = [10001, None, 0, 12000, 9999]
        for index in range(count):
            now += rng.randint(1, 25)
            events.append({
                "created_at": now,
                "amount": rng.choice(amounts),
                "resource": "https://api.example",
                "outcome": "denied_policy",
                "label": int(index >= 2),
            })
        return events

    if kind == "resource_churn":
        count = rng.randint(6, 12)
        for index in range(count):
            now += rng.randint(2, 30)
            events.append({
                "created_at": now,
                "amount": rng.randint(100, 350),
                "resource": f"https://service-{index}.example",
                "outcome": "settled",
                "label": int(index >= 3),
            })
        return events

    if kind == "slow_drain":
        count = rng.randint(4, 7)
        for index in range(count):
            now += rng.randint(65 * 60, 4 * 3600)
            events.append({
                "created_at": now,
                "amount": rng.randint(7000, 9999),
                "resource": "https://api.example",
                "outcome": "settled" if index < 3 else "denied_budget",
                "label": int(index >= 1),
            })
        return events

    raise ValueError(f"Unknown synthetic session kind: {kind}")


def generate_rows(sessions_per_kind: int = 400, seed: int = 42) -> list[dict[str, Any]]:
    """Return causal feature rows; all rows from a session share its split key."""
    if sessions_per_kind < 20:
        raise ValueError("Use at least 20 sessions per kind for a useful split.")
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    kinds = ("normal",) + ATTACK_KINDS
    for kind in kinds:
        session_count = sessions_per_kind * (3 if kind == "normal" else 1)
        for session_index in range(session_count):
            session_id = f"{kind}-{session_index:06d}"
            history: list[dict[str, Any]] = []
            for event_index, event in enumerate(_session_events(kind, rng)):
                features = build_features(
                    amount=event["amount"],
                    resource=event["resource"],
                    history=history,
                    now=event["created_at"],
                    max_amount=10_000,
                    hourly_budget=10_000,
                    daily_budget=30_000,
                )
                rows.append({
                    **features,
                    "session_id": session_id,
                    "session_kind": kind,
                    "event_index": event_index,
                    "label": event["label"],
                })
                history.append(event)
    rng.shuffle(rows)
    return rows


__all__ = ["ATTACK_KINDS", "FEATURE_NAMES", "generate_rows"]
