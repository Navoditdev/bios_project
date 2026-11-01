"""Run a full x402 HTTP round trip using the official SDK and a fake signer.

The signer returns a conspicuous placeholder byte string, not a valid ECDSA
signature. The local server accepts only that exact mock marker.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from client import parse_payment_requirements
from behavior_risk import BehaviorRiskMonitor
from payer_agent import DeterministicPaymentAgent, InMemorySpendLedger
from x402.http import encode_payment_signature_header


MOCK_PAYER = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
MOCK_SIGNATURE_BYTES = b"MOCK-ONLY-NOT-A-REAL-ECDSA-SIGNATURE"
MOCK_SIGNATURE_HEX = "0x" + MOCK_SIGNATURE_BYTES.hex()
# Share one prototype ledger across all mock payer calls in this process.
MOCK_PAYER_LEDGER = InMemorySpendLedger()
MOCK_BEHAVIOR_MONITOR = BehaviorRiskMonitor()


def _json_safe(value: Any) -> Any:
    """Turn SDK byte values into readable hex for logs and browser JSON."""
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


class MockEvmSigner:
    """Implements the official ClientEvmSigner interface without a private key."""

    address = MOCK_PAYER

    def __init__(self) -> None:
        self.last_signing_request: dict[str, Any] | None = None
        self.last_payment_payload: dict[str, Any] | None = None
        self.parsed_requirements: dict[str, Any] | None = None
        self.modified_requirements: dict[str, Any] | None = None
        self.attack: dict[str, str] | None = None
        self.sign_calls = 0
        self.signing_attempted = False
        self.retry_sent = False
        self.payer_decision: dict[str, Any] | None = None
        self.server_guard_evaluated = False

    def sign_typed_data(self, domain, types, primary_type, message) -> bytes:
        """Capture the EIP-712 request and return a deliberately fake signature."""
        self.sign_calls += 1
        self.signing_attempted = True
        self.last_signing_request = {
            "domain": asdict(domain) if is_dataclass(domain) else domain.model_dump(),
            "types": {
                name: [
                    asdict(field) if is_dataclass(field) else field.model_dump()
                    for field in fields
                ]
                for name, fields in types.items()
            },
            "primary_type": primary_type,
            "message": _json_safe(message),
        }
        return MOCK_SIGNATURE_BYTES


def _request(url: str, payment_header: str | None = None) -> tuple[int, Any, bytes]:
    headers = {"PAYMENT-SIGNATURE": payment_header} if payment_header else {}
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read()
    except HTTPError as error:
        result = (error.code, error.headers, error.read())
        error.close()
        return result
    except URLError as error:
        raise RuntimeError(f"Could not reach {url}: {error.reason}") from error


def perform_mock_payment(
    url: str,
    attack_field: str | None = None,
    attack_value: str | None = None,
    requirements_override_for_test: Any | None = None,
) -> tuple[int, dict[str, str], dict[str, Any], MockEvmSigner]:
    """Run parser → optional challenge tamper → SDK signer → guarded retry.

    ``attack_field`` is intentionally limited to the four offer fields exposed
    by the local red-team UI. The attack changes what the buyer sees in the
    402 response; the resource server's original terms stay unchanged.
    """
    status, headers, _ = _request(url)
    if status != 402:
        raise RuntimeError(f"Expected initial HTTP 402, received HTTP {status}")

    signer = MockEvmSigner()
    signer.attack = {"field": attack_field, "value": attack_value} if attack_field else None
    agent = DeterministicPaymentAgent(
        signer=signer,
        ledger=MOCK_PAYER_LEDGER,
        behavior_monitor=MOCK_BEHAVIOR_MONITOR,
    )
    challenge_header = headers.get("PAYMENT-REQUIRED")
    if not challenge_header:
        signer.payer_decision = agent.deny_malformed_offer(
            "HTTP 402 response is missing the PAYMENT-REQUIRED header"
        ).to_dict()
        return (
            402,
            {},
            {"error": "Blocked before signing: missing PAYMENT-REQUIRED", "paymentMode": "blocked"},
            signer,
        )

    # First use our existing HTTP 402 parser. This step should only decode and
    # validate the envelope's shape; it does not decide whether the offer is
    # honest or consistent with the server's configuration.
    try:
        parsed_requirements = parse_payment_requirements(challenge_header)
    except Exception as error:
        signer.payer_decision = agent.deny_malformed_offer(
            f"HTTP 402 parser rejected the challenge: {error}"
        ).to_dict()
        return (
            402,
            {},
            {
                "error": "Blocked before signing: malformed PAYMENT-REQUIRED",
                "paymentMode": "blocked",
            },
            signer,
        )

    modified_requirements = json.loads(json.dumps(parsed_requirements))
    if attack_field:
        if attack_field not in {"amount", "recipient", "asset", "network"}:
            raise ValueError(f"Unsupported red-team field: {attack_field}")
        if not attack_value:
            raise ValueError("A red-team value is required")
        # Recipient is represented as `payTo` in the x402 payment offer.
        target_field = "payTo" if attack_field == "recipient" else attack_field
        modified_requirements["accepts"][0][target_field] = attack_value

    signer.parsed_requirements = parsed_requirements
    if requirements_override_for_test is not None:
        # Internal injection hook for focused tests of malformed/ambiguous
        # requirements; the public GUI only exposes the four named attacks.
        modified_requirements = requirements_override_for_test
    signer.modified_requirements = modified_requirements

    # Payer-side policy is the decision point. It checks trusted limits before
    # the SDK receives the offer or the signer can be called.
    payer_decision, payment_payload = agent.authorize_then_build_payload(
        modified_requirements,
        url,
    )
    signer.payer_decision = payer_decision.to_dict()
    if payment_payload is None:
        # Preserve the original 402 as the outcome: the agent stopped before
        # signing and deliberately did not send a payment retry.
        return (
            402,
            {},
            {"error": "Blocked by payer-side policy before signing", "paymentMode": "blocked"},
            signer,
        )

    signer.last_payment_payload = payment_payload.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    payment_header = encode_payment_signature_header(payment_payload)

    # A retry is only possible after payer policy allows and SDK signing runs.
    signer.retry_sent = True
    MOCK_BEHAVIOR_MONITOR.record_outcome(agent.last_behavior_event_id, "submitted")
    status, response_headers, body = _request(url, payment_header)
    if agent.last_reservation_id:
        if status == 200:
            agent.ledger.settle(agent.last_reservation_id)
            MOCK_BEHAVIOR_MONITOR.record_outcome(agent.last_behavior_event_id, "settled_mock")
        elif status == 402:
            agent.ledger.release(agent.last_reservation_id)
            MOCK_BEHAVIOR_MONITOR.record_outcome(agent.last_behavior_event_id, "denied_server")
    signer.server_guard_evaluated = True
    response_json = json.loads(body)
    printable_headers = {
        name: response_headers.get(name)
        for name in ("PAYMENT-RESPONSE",)
        if response_headers.get(name)
    }
    return status, printable_headers, response_json, signer


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8402/paid")
    args = parser.parse_args()
    try:
        status, headers, body, signer = perform_mock_payment(args.url)
    except (RuntimeError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")

    print("Signer mode: MOCK (no private key; returned bytes are not a real signature)")
    print("SDK operation: ExactEvmScheme -> ClientEvmSigner.sign_typed_data(...)")
    print(json.dumps(signer.last_signing_request, indent=2, default=str))
    print(f"Mock signature bytes returned: {MOCK_SIGNATURE_BYTES!r}")
    print(f"Retry response: HTTP {status}")
    print(json.dumps(body, indent=2))
    if headers.get("PAYMENT-RESPONSE"):
        print(f"PAYMENT-RESPONSE (base64): {headers['PAYMENT-RESPONSE']}")


if __name__ == "__main__":
    main()
