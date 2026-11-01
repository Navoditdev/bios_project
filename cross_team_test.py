"""Dry-run shared x402 suite runner. This module never creates a signer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from attack_suite import (
    RESOURCE_URL,
    SCENARIOS,
    offer_for_scenario,
)
from behavior_risk import BehaviorRiskMonitor
from payer_agent import DeterministicPaymentAgent


def evaluate_local(scenario_id: str, offer: Any) -> dict[str, Any]:
    """Evaluate against this process's trusted default policy, without signing."""
    if scenario_id in {"multiple_calls", "small_payment_flood"} and isinstance(offer, list):
        monitor = BehaviorRiskMonitor(database_path=":memory:")
        agent = DeterministicPaymentAgent(behavior_monitor=monitor)
        call_decisions = [
            agent.authorize_and_reserve(call, RESOURCE_URL)[0]
            for call in offer
        ]
        monitor.close()
        checks = [
            {
                "name": f"call_{index}.{check.name}",
                "passed": check.passed,
                "detail": check.detail,
            }
            for index, decision in enumerate(call_decisions, start=1)
            for check in decision.checks
        ]
        authorized = all(decision.authorized for decision in call_decisions)
        return {
            "scenario_id": scenario_id,
            "authorized": authorized,
            "checks": checks,
            "reasons": [check["detail"] for check in checks if not check["passed"]],
            "call_results": [decision.authorized for decision in call_decisions],
            "signing_attempted": False,
            "payment_submitted": False,
        }
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


def evaluate_peer(
    endpoint: str,
    scenario_id: str,
    offer: Any,
    timeout: float,
) -> dict[str, Any]:
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
        raise RuntimeError(
            "peer response 'checks' must contain name, boolean passed, "
            "and detail fields"
        )
    if not isinstance(result.get("reasons"), list) or not all(
        isinstance(reason, str) for reason in result["reasons"]
    ):
        raise RuntimeError("peer response 'reasons' must be a list of strings")
    for flag in ("signing_attempted", "payment_submitted"):
        if type(result.get(flag)) is not bool:
            raise RuntimeError(f"peer response is missing boolean '{flag}'")
        if result[flag]:
            raise RuntimeError(f"peer dry-run violated contract: {flag} must be false")
    if scenario_id in {"multiple_calls", "small_payment_flood"}:
        call_results = result.get("call_results")
        if (
            not isinstance(call_results, list)
            or len(call_results) != len(offer)
            or not all(type(allowed) is bool for allowed in call_results)
        ):
            raise RuntimeError(
                "peer response 'call_results' must contain one boolean per offer"
            )
        if result["authorized"] is not all(call_results):
            raise RuntimeError(
                "peer response 'authorized' must match the aggregate call_results"
            )
    return result


def run_suite(
    endpoint: str | None = None,
    timeout: float = 5.0,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
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
            if scenario.scenario_id in {"multiple_calls", "small_payment_flood"}:
                result["call_results"] = decision["call_results"]
                if scenario.scenario_id == "multiple_calls":
                    result["passed"] = decision["call_results"] == [True, False, False]
                else:
                    calls = decision["call_results"]
                    result["passed"] = (
                        decision["authorized"] is False
                        and any(calls)
                        and any(not allowed for allowed in calls)
                    )
            result["attack_succeeded"] = bool(
                scenario.attack_class
                and scenario.expected_authorized is False
                and decision["authorized"]
            )
        except TimeoutError as error:
            result["error"] = str(error)
            result["timed_out"] = True
        except Exception as error:
            result["error"] = str(error)
        results.append(result)
        if on_result is not None:
            on_result(result)

    baseline = next(result for result in results if result["scenario_id"] == "baseline_valid")
    attacks = [result for result in results if result["attack_class"]]
    return {
        "mode": "peer_http_dry_run" if endpoint else "local_payer_guard_dry_run",
        "endpoint": endpoint,
        "results": results,
        "summary": {
            "baseline_passed": baseline["passed"],
            "overpayment_blocked": next(
                r["actual"] == "deny"
                for r in attacks
                if r["scenario_id"] == "overpayment"
            ),
            "wrong_party_blocked": next(
                r["actual"] == "deny"
                for r in attacks
                if r["scenario_id"] == "wrong_party"
            ),
            "multiple_calls_blocked": next(
                r["actual"] == "deny"
                for r in attacks
                if r["scenario_id"] == "multiple_calls"
            ),
            "small_payment_flood_detected": next(
                r["passed"]
                for r in attacks
                if r["scenario_id"] == "small_payment_flood"
            ),
            "attacks_succeeded": [r["scenario_id"] for r in attacks if r["attack_succeeded"]],
            "all_scenarios_passed": all(result["passed"] for result in results),
        },
    }


def print_demo_result(result: dict[str, Any], verbose: bool = False) -> None:
    """Print one completed evaluation; outcomes always come from the guard."""
    status = "ERROR" if result["error"] else ("PASS" if result["passed"] else "FAIL")
    expected = "ALLOW" if result["expected_authorized"] else "DENY"
    actual = (result["actual"] or "ERROR").upper()
    print(f"\n[{status}] {result['title']}", flush=True)
    print(f"  Expected: {expected} | Actual: {actual}", flush=True)
    if result["error"]:
        print(f"  Error: {result['error']}", flush=True)
        return
    if "call_results" in result:
        calls = " -> ".join("ALLOW" if allowed else "DENY" for allowed in result["call_results"])
        print(f"  Calls: {calls}", flush=True)
    checks = result["checks"]
    failed = [check for check in checks if not check["passed"]]
    print(f"  Checks: {sum(check['passed'] for check in checks)}/{len(checks)} satisfied", flush=True)
    # A denied attack is a passing test; failed policy checks explain the denial.
    for check in checks if verbose else failed[:2]:
        label = "OK" if check["passed"] else "BLOCK"
        print(f"    {label} {check['name']}: {check['detail']}", flush=True)
    if not verbose and len(failed) > 2:
        print(f"    + {len(failed) - 2} more blocking checks (use --verbose)", flush=True)
    print("  Signer called: " + ("yes" if result["signing_attempted"] else "no")
          + " | Payment submitted: " + ("yes" if result["payment_submitted"] else "no"), flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "--local",
        action="store_true",
        help="run against the local payer policy (default)",
    )
    target.add_argument(
        "--endpoint",
        help="peer dry-run endpoint URL, e.g. http://127.0.0.1:8402/evaluate",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="per-scenario peer request timeout in seconds",
    )
    parser.add_argument("--demo", action="store_true", help="show readable, live per-case results for a terminal demonstration")
    parser.add_argument("--verbose", action="store_true", help="with --demo, show every policy check instead of only blocking checks")
    parser.add_argument("--report", type=Path, help="also save the complete JSON report to this file")
    args = parser.parse_args(argv)
    if args.verbose and not args.demo:
        parser.error("--verbose requires --demo")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    if args.demo:
        print("NexVault | Adversarial payment guard tests", flush=True)
        print("Target: " + (args.endpoint or "local Python payer guard (no server or browser required)"), flush=True)
        print(f"Running {len(SCENARIOS)} cases against the real guard implementation.", flush=True)
        print("Decision-only dry run: no signer is created and no funds are transferred.", flush=True)
        print("PASS means the actual decision matched the expected test outcome.", flush=True)
    report = run_suite(
        args.endpoint, args.timeout,
        on_result=(lambda result: print_demo_result(result, args.verbose)) if args.demo else None,
    )
    if args.report:
        try:
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            print(f"Could not save report: {error}", file=sys.stderr)
            return 1
        print(f"\nFull JSON report saved to {args.report}", file=sys.stderr)
    if args.demo:
        passed = sum(result["passed"] for result in report["results"])
        print(f"\nResult: {passed}/{len(report['results'])} cases passed")
    else:
        print(json.dumps(report, indent=2))
    summary = report["summary"]
    print("\nSummary:")
    print(f"  Baseline passed: {'yes' if summary['baseline_passed'] else 'NO'}")
    print(
        "  Overpayment blocked: "
        f"{'yes' if summary['overpayment_blocked'] else 'NO / endpoint error'}"
    )
    print(
        "  Wrong-party blocked: "
        f"{'yes' if summary['wrong_party_blocked'] else 'NO / endpoint error'}"
    )
    print(
        "  Repeated-call burst blocked: "
        f"{'yes' if summary['multiple_calls_blocked'] else 'NO / endpoint error'}"
    )
    print(f"  Small-payment flood detected: {'yes' if summary['small_payment_flood_detected'] else 'NO / endpoint error'}")
    print(f"  All scenarios passed: {'yes' if summary['all_scenarios_passed'] else 'NO'}")
    return 0 if summary["all_scenarios_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
