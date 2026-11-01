"""Stable cross-team x402 offer scenarios (fixtures, never policy inputs)."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


RESOURCE_URL = "https://cross-team.invalid/protected-resource"
APPROVED_RECIPIENT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
BASE_SEPOLIA = "eip155:84532"
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    expected_authorized: bool
    attack_class: str | None = None
    description: str = ""


# Keep the baseline and core attack classes first and prominent.
OFFICIAL_SCENARIOS = (
    Scenario(
        "baseline_valid",
        "Valid payment at cap",
        True,
        description="10,000 atomic units to the approved recipient.",
    ),
    Scenario(
        "overpayment",
        "Overpayment",
        False,
        "overpayment",
        "10,001 atomic units to the approved recipient.",
    ),
    Scenario(
        "wrong_party",
        "Wrong party",
        False,
        "wrong_party",
        "10,000 atomic units to an unapproved recipient.",
    ),
    Scenario(
        "multiple_calls",
        "Repeated valid payments",
        False,
        "multiple_calls",
        "Three individually valid 10,000-unit calls arrive within one rolling "
        "hour; the 10,000-unit hourly budget should allow only the first.",
    ),
)

SUPPORTING_SCENARIOS = (
    Scenario(
        "small_payment_flood",
        "Small-payment flood",
        False,
        "behavioral_anomaly",
        "Eight rapid 1,000-unit calls total 8,000 units, below the hourly spend cap; the XGBoost behavior monitor should detect the burst.",
    ),
    Scenario(
        "malformed_amount",
        "Malformed amount",
        False,
        description="Amount is not an integer atomic-unit string.",
    ),
    Scenario(
        "missing_options",
        "Missing payment options",
        False,
        description="The x402 offer has no accepts field.",
    ),
    Scenario(
        "ambiguous_options",
        "Ambiguous payment options",
        False,
        description="The x402 offer has multiple accepted options.",
    ),
)

SCENARIOS = OFFICIAL_SCENARIOS + SUPPORTING_SCENARIOS
SCENARIOS_BY_ID = {scenario.scenario_id: scenario for scenario in SCENARIOS}


def offer_for_scenario(scenario_id: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Return a fresh x402 v2 offer (or call sequence) for a suite scenario."""
    try:
        scenario = SCENARIOS_BY_ID[scenario_id]
    except KeyError as error:
        raise ValueError(f"Unknown scenario_id: {scenario_id}") from error

    offer: dict[str, Any] = {
        "x402Version": 2,
        "resource": {"url": RESOURCE_URL, "description": "Cross-team dry-run fixture"},
        "accepts": [
            {
                "scheme": "exact",
                "network": BASE_SEPOLIA,
                "amount": "10000",
                "asset": BASE_SEPOLIA_USDC,
                "payTo": APPROVED_RECIPIENT,
                "maxTimeoutSeconds": 60,
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
    }
    if scenario_id == "overpayment":
        offer["accepts"][0]["amount"] = "10001"
    elif scenario_id == "wrong_party":
        offer["accepts"][0]["payTo"] = "0x0000000000000000000000000000000000000001"
    elif scenario_id == "malformed_amount":
        offer["accepts"][0]["amount"] = "ten thousand"
    elif scenario_id == "missing_options":
        del offer["accepts"]
    elif scenario_id == "ambiguous_options":
        offer["accepts"].append(deepcopy(offer["accepts"][0]))
    elif scenario_id == "multiple_calls":
        return [deepcopy(offer) for _ in range(3)]
    elif scenario_id == "small_payment_flood":
        offer["accepts"][0]["amount"] = "1000"
        return [deepcopy(offer) for _ in range(8)]
    return offer


def scenario_catalog() -> list[dict[str, Any]]:
    """JSON-safe metadata; expected outcomes are test labels, not policy."""
    return [
        {
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "expected_authorized": scenario.expected_authorized,
            "attack_class": scenario.attack_class,
            "description": scenario.description,
        }
        for scenario in SCENARIOS
    ]
