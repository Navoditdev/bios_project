"""Dry-run shared x402 suite runner. This module never creates a signer."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from attack_suite import (
    RESOURCE_URL,
    SCENARIOS,
    offer_for_scenario,
)
from payer_agent import DeterministicPaymentAgent


def evaluate_local(scenario_id: str, offer: Any) -> dict[str, Any]:
    """Evaluate against this process's trusted default policy, without signing."""
    agent = DeterministicPaymentAgent()  # No signer is supplied or instantiated.
    decision = agent.evaluate(offer, RESOURCE_URL)
    return {
        "scenario_id": scenario_id,
        "authorized": decision.authorized,
        "checks": [check.__dict__ for check in decision.checks],
        "reasons": decision.reasons,
        "signing_attempted": False,
        "payment_submitted": False,
    }


def evaluate_peer(endpoint: str, scenario_id: str, offer: dict[str, Any], timeout: float) -> dict[str, Any]:
    """POST only the stable scenario ID and its untrusted x402 offer."""
    body = json.dumps({"scenario_id": scenario_id, "offer": offer}).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            if response.status != 200:
                raise RuntimeError(f"peer endpoint returned HTTP {response.status}")
    except HTTPError as error:
        details = error.read(2048).decode("utf-8", "replace")
        error.close()
        raise RuntimeError(f"peer endpoint returned HTTP {error.code}: {details}") from error
    except (URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, TimeoutError):
            raise TimeoutError(f"peer endpoint timed out after {timeout:g}s") from error
        raise RuntimeError(f"peer endpoint unavailable: {reason}") from error

    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("peer endpoint returned malformed JSON") from error
    if not isinstance(result, dict):
        raise RuntimeError("peer response must be a JSON object")
    if result.get("scenario_id") != scenario_id:
        raise RuntimeError("peer response scenario_id did not match request")
    if type(result.get("authorized")) is not bool:
        raise RuntimeError("peer response is missing boolean 'authorized'")
    if not isinstance(result.get("checks"), list) or not all(
        isinstance(check, dict)
        and isinstance(check.get("name"), str)
        and type(check.get("passed")) is bool
        and isinstance(check.get("detail"), str)
        for check in result["checks"]
    ):
        raise RuntimeError("peer response 'checks' must contain name, boolean passed, and detail fields")
    if not isinstance(result.get("reasons"), list) or not all(
        isinstance(reason, str) for reason in result["reasons"]
    ):
        raise RuntimeError("peer response 'reasons' must be a list of strings")
    for flag in ("signing_attempted", "payment_submitted"):
        if type(result.get(flag)) is not bool:
            raise RuntimeError(f"peer response is missing boolean '{flag}'")
        if result[flag]:
            raise RuntimeError(f"peer dry-run violated contract: {flag} must be false")
    return result


def run_suite(endpoint: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    """Run all fixed fixtures locally or against a peer HTTP evaluation API."""
    results: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        offer = offer_for_scenario(scenario.scenario_id)
        result: dict[str, Any] = {
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "attack_class": scenario.attack_class,
            "expected_authorized": scenario.expected_authorized,
            "actual": None,
            "checks": [],
            "reasons": [],
            "error": None,
            "timed_out": False,
            "passed": False,
            "attack_succeeded": False,
            "signing_attempted": False,
            "payment_submitted": False,
        }
        try:
            decision = (
                evaluate_peer(endpoint, scenario.scenario_id, offer, timeout)
                if endpoint
                else evaluate_local(scenario.scenario_id, offer)
            )
            result["actual"] = "allow" if decision["authorized"] else "deny"
            result["checks"] = decision["checks"]
            result["reasons"] = decision["reasons"]
            result["signing_attempted"] = decision["signing_attempted"]
            result["payment_submitted"] = decision["payment_submitted"]
            result["passed"] = decision["authorized"] is scenario.expected_authorized
            result["attack_succeeded"] = bool(
                scenario.attack_class and scenario.expected_authorized is False and decision["authorized"]
            )
        except TimeoutError as error:
            result["error"] = str(error)
            result["timed_out"] = True
        except Exception as error:
            result["error"] = str(error)
        results.append(result)

    baseline = next(result for result in results if result["scenario_id"] == "baseline_valid")
    attacks = [result for result in results if result["attack_class"]]
    return {
        "mode": "peer_http_dry_run" if endpoint else "local_payer_guard_dry_run",
        "endpoint": endpoint,
        "results": results,
        "summary": {
            "baseline_passed": baseline["passed"],
            "overpayment_blocked": next(r["actual"] == "deny" for r in attacks if r["scenario_id"] == "overpayment"),
            "wrong_party_blocked": next(r["actual"] == "deny" for r in attacks if r["scenario_id"] == "wrong_party"),
            "attacks_succeeded": [r["scenario_id"] for r in attacks if r["attack_succeeded"]],
            "all_scenarios_passed": all(result["passed"] for result in results),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--local", action="store_true", help="run against the local payer policy (default)")
    target.add_argument("--endpoint", help="peer dry-run endpoint URL, e.g. http://127.0.0.1:8402/evaluate")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-scenario peer request timeout in seconds")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    report = run_suite(args.endpoint, args.timeout)
    print(json.dumps(report, indent=2))
    summary = report["summary"]
    print("\nSummary:")
    print(f"  Baseline passed: {'yes' if summary['baseline_passed'] else 'NO'}")
    print(f"  Overpayment blocked: {'yes' if summary['overpayment_blocked'] else 'NO / endpoint error'}")
    print(f"  Wrong-party blocked: {'yes' if summary['wrong_party_blocked'] else 'NO / endpoint error'}")
    print(f"  All scenarios passed: {'yes' if summary['all_scenarios_passed'] else 'NO'}")
    return 0 if summary["all_scenarios_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
