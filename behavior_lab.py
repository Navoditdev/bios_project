"""Fixed, deterministic behavioral attack sequences for the local demo."""

from __future__ import annotations

from typing import Any

from behavior_risk import BehaviorRiskMonitor
from payer_agent import DeterministicPaymentAgent, InMemorySpendLedger


BASE_RESOURCE = "https://service-0.behavior-demo.invalid/paid"
APPROVED_RECIPIENT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
APPROVED_ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
APPROVED_NETWORK = "eip155:84532"

SCENARIOS = (
    {
        "scenario_id": "small_payment_flood",
        "title": "Small-payment flood",
        "description": "Eight rapid 1,000-unit payments; total spend stays below the hourly budget.",
        "attack_pattern": "Rapid repeated requests evade a per-payment cap.",
    },
    {
        "scenario_id": "near_cap_burst",
        "title": "Near-cap burst",
        "description": "Repeated 9,500-unit requests arrive in seconds, each individually under the per-payment limit.",
        "attack_pattern": "Repeated near-limit calls try to drain a wallet without crossing the single-call ceiling.",
    },
    {
        "scenario_id": "policy_probe",
        "title": "Policy probing",
        "description": "Malformed, zero, and over-limit amounts are interleaved with valid-looking requests.",
        "attack_pattern": "An attacker probes the payer policy and keeps retrying after denials.",
    },
    {
        "scenario_id": "resource_churn",
        "title": "Resource churn",
        "description": "Small payments arrive rapidly from a sequence of previously unseen resource origins.",
        "attack_pattern": "The attacker rotates resource hosts to make a burst look like unrelated activity.",
    },
    {
        "scenario_id": "slow_drain",
        "title": "Slow drain",
        "description": "Near-cap requests are spaced 90 minutes apart, then accumulate inside the rolling day.",
        "attack_pattern": "The attacker stays below the hourly burst signal while steadily draining the daily budget.",
    },
)

_SCENARIOS_BY_ID = {item["scenario_id"]: item for item in SCENARIOS}


def scenario_catalog() -> list[dict[str, str]]:
    return [dict(scenario) for scenario in SCENARIOS]


def _events(scenario_id: str) -> list[tuple[int | str, str, int]]:
    """Return (amount, resource URL, simulated offset in seconds)."""
    if scenario_id == "small_payment_flood":
        return [(1000, BASE_RESOURCE, index * 5) for index in range(8)]
    if scenario_id == "near_cap_burst":
        return [(9500, BASE_RESOURCE, index * 8) for index in range(6)]
    if scenario_id == "policy_probe":
        amounts = ("10001", "0", "not-an-amount", "9999", "12000", "10001", "9999")
        return [
            (amount, BASE_RESOURCE, index * 12)
            for index, amount in enumerate(amounts)
        ]
    if scenario_id == "resource_churn":
        return [
            (400, f"https://service-{index}.behavior-demo.invalid/paid", index * 4)
            for index in range(8)
        ]
    if scenario_id == "slow_drain":
        return [(9000, BASE_RESOURCE, index * 90 * 60) for index in range(6)]
    raise ValueError(f"Unknown behavior scenario: {scenario_id}")


def _risk_axes(points: list[dict[str, Any]]) -> dict[str, float]:
    features = [point["features"] for point in points]
    maxima = lambda name: max((row.get(name, 0.0) for row in features), default=0.0)
    scale = lambda value, denominator: round(min(max(value / denominator, 0.0), 1.0) * 100, 1)
    intervals = [
        row.get("seconds_since_last_call", 0.0)
        for row in features
        if row.get("calls_24h", 0.0) > 0
    ]
    return {
        "Burst rate": scale(maxima("calls_5m"), 8),
        "Hourly spend": scale(maxima("units_1h_hour_budget_ratio"), 1.0),
        "Daily spend": scale(maxima("units_24h_day_budget_ratio"), 1.0),
        "Near-cap use": scale(maxima("near_cap_calls_24h"), 5),
        "Resource churn": scale(maxima("unique_resources_1h"), 8),
        "Denial streak": scale(maxima("denials_5m"), 5),
        "Repeated amount": scale(maxima("same_amount_calls_5m"), 7),
        "Slow pacing": scale(max(intervals, default=0.0), 5400),
    }


def run_scenario(scenario_id: str) -> dict[str, Any]:
    """Run a canned attack sequence through the real payer checks and model."""
    if scenario_id not in _SCENARIOS_BY_ID:
        raise ValueError(f"Unknown behavior scenario: {scenario_id}")

    start = 1_700_000_000.0
    simulated_time = [start]
    clock = lambda: simulated_time[0]
    monitor = BehaviorRiskMonitor(database_path=":memory:", clock=clock)
    ledger = InMemorySpendLedger(clock=clock)
    agent = DeterministicPaymentAgent(ledger=ledger, behavior_monitor=monitor)
    points: list[dict[str, Any]] = []
    total_allowed = 0

    for index, (amount, resource_url, offset) in enumerate(_events(scenario_id), start=1):
        simulated_time[0] = start + offset
        amount_string = str(amount)
        offer = {
            "x402Version": 2,
            "resource": {"url": resource_url, "description": "Behavior lab fixture"},
            "accepts": [{
                "scheme": "exact",
                "network": APPROVED_NETWORK,
                "amount": amount_string,
                "asset": APPROVED_ASSET,
                "payTo": APPROVED_RECIPIENT,
                "maxTimeoutSeconds": 60,
                "extra": {"name": "USDC", "version": "2"},
            }],
        }
        decision, _ = agent.authorize_and_reserve(offer, resource_url)
        checks = {check.name: check for check in decision.checks}
        risk_check = checks.get("anomaly_risk")
        features = dict(agent.last_behavior_features or {})
        assessment = agent.last_behavior_assessment
        score = assessment.score if assessment else None
        model_blocked = bool(risk_check and not risk_check.passed)
        allowed = decision.authorized
        failing_check = next((check for check in decision.checks if not check.passed), None)
        if model_blocked:
            blocked_by = "behavior model"
        elif failing_check and failing_check.name == "rolling_budget":
            blocked_by = "rolling budget"
        elif failing_check:
            blocked_by = "payer policy"
        else:
            blocked_by = None
        if allowed:
            total_allowed += int(amount) if amount_string.isdecimal() else 0
        points.append({
            "attempt": index,
            "offset_seconds": offset,
            "amount": amount_string,
            "allowed": allowed,
            "model_blocked": model_blocked,
            "blocked_by": blocked_by,
            "score": score,
            "features": features,
            "detail": risk_check.detail if risk_check else "No anomaly score returned.",
        })

    model_available = monitor.available
    threshold = monitor.threshold
    monitor.close()
    scores = [point["score"] for point in points if point["score"] is not None]
    first_model_block = next(
        (point["attempt"] for point in points if point["model_blocked"]), None
    )
    first_block = next((point["attempt"] for point in points if not point["allowed"]), None)
    return {
        "scenario_id": scenario_id,
        "title": _SCENARIOS_BY_ID[scenario_id]["title"],
        "model_available": model_available,
        "threshold": threshold,
        "points": points,
        "risk_axes": _risk_axes(points),
        "summary": {
            "attempts": len(points),
            "allowed": sum(point["allowed"] for point in points),
            "blocked": sum(not point["allowed"] for point in points),
            "model_blocks": sum(point["model_blocked"] for point in points),
            "first_model_block_attempt": first_model_block,
            "first_block_attempt": first_block,
            "peak_risk": max(scores, default=None),
            "allowed_atomic_units": total_allowed,
        },
    }
