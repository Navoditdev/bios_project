"""A tiny x402 v2 HTTP resource server for local protocol prototyping.

This server simulates verification and settlement. It MUST NOT be used to gate
real resources or accept real payments; see README.md.
"""

from __future__ import annotations

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from attack_suite import offer_for_scenario, scenario_catalog
from payment_guard import GuardConfig, PaymentGuard
from payer_agent import DeterministicPaymentAgent


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8402"))
PAY_TO = os.environ.get("X402_PAY_TO", "0x209693Bc6afc0C5328bA36FaF03C514EF312287C")
PRICE = os.environ.get("X402_AMOUNT", "10000")  # 0.01 USDC (6 decimals)
NETWORK = "eip155:84532"  # Base Sepolia
ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"  # Base Sepolia USDC
DESCRIPTION = "Demo premium resource"
# Must match mock_pay.MOCK_SIGNATURE_HEX. It is a marker, never a valid ECDSA signature.
MOCK_SIGNATURE = "0x" + b"MOCK-ONLY-NOT-A-REAL-ECDSA-SIGNATURE".hex()
MOCK_PAYER = "0x857b06519E91e3A54538791bDbb0E22373e36b66"
CROSS_TEAM_RESOURCE_URL = "https://cross-team.invalid/protected-resource"
# Decision-only agent: intentionally has no signer and uses server-configured
# defaults. Request bodies can supply offers, never policy settings.
CROSS_TEAM_AGENT = DeterministicPaymentAgent()

# This one guard instance remembers used nonces for the lifetime of this
# process. It is deliberately reset whenever you restart the local demo.
PAYMENT_GUARD = PaymentGuard(
    GuardConfig(
        scheme="exact",
        network=NETWORK,
        amount=PRICE,
        asset=ASSET,
        pay_to=PAY_TO,
        mock_signature=MOCK_SIGNATURE,
        allowed_payers=frozenset({MOCK_PAYER}),
        max_timeout_seconds=60,
    )
)


def encode_header(value: dict[str, Any]) -> str:
    """Encode compact JSON as required by x402 v2 HTTP headers."""
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_header(value: str) -> dict[str, Any] | None:
    try:
        decoded = base64.b64decode(value, validate=True)
        result = json.loads(decoded)
        return result if isinstance(result, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def payment_requirements(resource_url: str, error: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "x402Version": 2,
        "resource": {
            "url": resource_url,
            "description": DESCRIPTION,
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": NETWORK,
                "amount": PRICE,
                "asset": ASSET,
                "payTo": PAY_TO,
                "maxTimeoutSeconds": 60,
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
    }
    if error:
        result["error"] = error
    return result


class X402Handler(BaseHTTPRequestHandler):
    server_version = "bios-x402-prototype/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep local test output quiet; standard HTTP access logs are not needed.
        return

    def send_json(
        self,
        status: int,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def send_html(self, html: str) -> None:
        """Serve the explanatory page as a plain same-origin local demo."""
        encoded = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def send_html_file(self, filename: str) -> None:
        """Serve a static demo page stored beside this module."""
        html_path = Path(__file__).with_name(filename)
        self.send_html(html_path.read_text(encoding="utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/cross-team":
            self.send_html_file("cross_team_gui.html")
            return
        if parsed.path == "/cross-team/scenarios":
            scenarios = scenario_catalog()
            for scenario in scenarios:
                scenario["offer"] = offer_for_scenario(scenario["scenario_id"])
            self.send_json(200, {"scenarios": scenarios})
            return
        if parsed.path == "/demo":
            self.send_html_file("demo.html")
            return
        if parsed.path == "/demo/run":
            # The demo endpoint runs a separate mock client through the same
            # HTTP route below, then returns the request details and guard log
            # to the page. This route is for localhost learning only.
            from mock_pay import MOCK_SIGNATURE_HEX, perform_mock_payment

            resource_url = f"http://{self.headers.get('Host', f'{HOST}:{PORT}')}/paid"
            query = parse_qs(parsed.query)
            attack_field = query.get("attack", [None])[0]
            attack_value = query.get("value", [None])[0]
            try:
                status, response_headers, body, signer = perform_mock_payment(
                    resource_url,
                    attack_field=attack_field,
                    attack_value=attack_value,
                )
            except Exception as error:
                self.send_json(500, {"error": str(error), "mode": "mock"})
                return
            receipt_header = response_headers.get("PAYMENT-RESPONSE")
            receipt = decode_header(receipt_header) if receipt_header else None
            decision = PAYMENT_GUARD.last_decision
            payer_denied = bool(
                signer.payer_decision and not signer.payer_decision["authorized"]
            )
            payer_allowed = bool(
                signer.payer_decision and signer.payer_decision["authorized"]
            )
            denial_reasons = (
                signer.payer_decision["reasons"] if payer_denied else []
            )
            red_team_result = (
                {
                    "succeeded": bool(
                        signer.attack and payer_denied and signer.signing_attempted
                    ),
                    "policy_violated": payer_denied,
                    "summary": (
                        "A policy-violating offer reached the signer. "
                        "The attack succeeded at the wallet boundary."
                        if payer_denied and signer.signing_attempted
                        else (
                            "The offer change still satisfies payer policy; "
                            "the attack was not successful."
                            if payer_allowed
                            else "The payer guard denied the offer before signing. "
                            "The attack was not successful."
                        )
                    ),
                    "why": denial_reasons,
                }
                if signer.attack
                else {
                    "succeeded": False,
                    "summary": "Baseline run: no red-team modification was attempted.",
                    "why": [],
                }
            )
            flow = [
                {
                    "step": 1,
                    "event": "GET /paid without payment",
                    "result": "HTTP 402 Payment Required",
                },
                {
                    "step": 2,
                    "event": "client.parse_payment_requirements",
                    "result": "Decoded and structurally checked the 402 offer",
                },
                {
                    "step": 3,
                    "event": "Red-team challenge tampering",
                    "result": (
                        "No change"
                        if not signer.attack
                        else f"Changed {signer.attack['field']} to {signer.attack['value']}"
                    ),
                },
                {
                    "step": 4,
                    "event": "DeterministicPaymentAgent policy",
                    "result": "ALLOW" if payer_allowed else "DENY",
                },
                {
                    "step": 5,
                    "event": "SDK signer invocation",
                    "result": (
                        "Called MockEvmSigner.sign_typed_data"
                        if signer.signing_attempted
                        else "BLOCKED; signer was not called"
                    ),
                },
                {
                    "step": 6,
                    "event": "Payment retry",
                    "result": f"HTTP {status}" if signer.retry_sent else "NOT SENT",
                },
                {
                    "step": 7,
                    "event": "Resource server guard",
                    "result": (
                        ("ALLOW" if decision and decision.authorized else "DENY")
                        if signer.server_guard_evaluated
                        else "NOT REACHED"
                    ),
                },
            ]
            self.send_json(
                # HTTP 200 here means the test run completed. The nested
                # resource response below separately shows whether /paid
                # allowed (200) or denied (402) the mock payment.
                200,
                {
                    "scenario": signer.attack or {"field": None, "value": None},
                    "red_team_result": red_team_result,
                    "flow": flow,
                    "original_parsed_requirements": signer.parsed_requirements,
                    "requirements_evaluated_by_payer": signer.modified_requirements,
                    "requirements_received_by_sdk": (
                        signer.modified_requirements if signer.signing_attempted else None
                    ),
                    "payer_guard_decision": signer.payer_decision,
                    "signing_attempted": signer.signing_attempted,
                    "signer_call_count": signer.sign_calls,
                    "retry_sent": signer.retry_sent,
                    "signing_request": signer.last_signing_request,
                    "mock_signature": MOCK_SIGNATURE_HEX,
                    "submitted_payload": signer.last_payment_payload,
                    "server_guard_evaluated": signer.server_guard_evaluated,
                    "server_guard_decision": (
                        decision.to_dict()
                        if signer.server_guard_evaluated and decision
                        else None
                    ),
                    "resource_response": body,
                    "payment_response": receipt,
                },
            )
            return
        if parsed.path == "/health":
            self.send_json(200, {"ok": True, "mode": "mock", "guard": "active"})
            return
        if parsed.path != "/paid":
            self.send_json(404, {"error": "not_found"})
            return

        resource_url = f"http://{self.headers.get('Host', f'{HOST}:{PORT}')}{parsed.path}"
        payment_header = self.headers.get("PAYMENT-SIGNATURE")
        if not payment_header:
            self.challenge(resource_url, "PAYMENT-SIGNATURE header is required")
            return

        payment = decode_header(payment_header)
        decision = PAYMENT_GUARD.authorize(payment, resource_url)
        if not decision.authorized:
            self.challenge(resource_url, "; ".join(decision.reasons))
            return

        # This response is deliberately marked as mocked. No cryptographic
        # signature is checked and no blockchain transaction is made.
        payer = payment["payload"]["authorization"]["from"]
        receipt = {
            "success": True,
            "transaction": "mock-not-settled",
            "network": NETWORK,
            "payer": payer,
        }
        self.send_json(
            200,
            {"data": "This is the x402 mock-paid demo resource.", "paymentMode": "mock"},
            {"PAYMENT-RESPONSE": encode_header(receipt)},
        )

    def do_POST(self) -> None:
        """Expose an evaluation-only API for cross-team guard comparisons."""
        if urlparse(self.path).path != "/evaluate":
            self.send_json(404, {"error": "not_found"})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "content_type_must_be_application_json"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(400, {"error": "invalid_content_length"})
            return
        if not 0 <= content_length <= 1_000_000:
            self.send_json(413, {"error": "request_body_too_large_or_empty"})
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "request_body_must_be_valid_json"})
            return
        if not isinstance(payload, dict) or set(payload) != {"scenario_id", "offer"}:
            self.send_json(400, {"error": "request_must_contain_only_scenario_id_and_offer"})
            return
        scenario_id = payload.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id or len(scenario_id) > 80:
            self.send_json(400, {"error": "scenario_id_must_be_a_non_empty_string"})
            return

        # The offer is untrusted. Even malformed offer values are evaluated
        # against fixed trusted policy and return a deny decision. This route
        # never calls the SDK, signer, resource payment handler, or settlement.
        if scenario_id == "multiple_calls":
            offers = payload["offer"]
            if not isinstance(offers, list) or not offers or len(offers) > 20:
                self.send_json(400, {"error": "multiple_calls_requires_one_to_twenty_offers"})
                return
            # Use a fresh ledger per scenario run, then evaluate each call
            # against the same rolling budget to model a burst of requests.
            agent = DeterministicPaymentAgent()
            decisions = [
                agent.authorize_and_reserve(offer, CROSS_TEAM_RESOURCE_URL)[0]
                for offer in offers
            ]
            checks = [
                {
                    "name": f"call_{index}.{check.name}",
                    "passed": check.passed,
                    "detail": check.detail,
                }
                for index, decision in enumerate(decisions, start=1)
                for check in decision.checks
            ]
            authorized = all(decision.authorized for decision in decisions)
            reasons = [check["detail"] for check in checks if not check["passed"]]
            call_results = [decision.authorized for decision in decisions]
        else:
            decision = CROSS_TEAM_AGENT.evaluate(payload["offer"], CROSS_TEAM_RESOURCE_URL)
            authorized = decision.authorized
            checks = [
                {"name": check.name, "passed": check.passed, "detail": check.detail}
                for check in decision.checks
            ]
            reasons = decision.reasons
            call_results = None
        self.send_json(
            200,
            {
                "scenario_id": scenario_id,
                "authorized": authorized,
                "checks": checks,
                "reasons": reasons,
                **({"call_results": call_results} if call_results is not None else {}),
                "signing_attempted": False,
                "payment_submitted": False,
            },
        )

    def challenge(self, resource_url: str, error: str) -> None:
        self.send_json(
            402,
            {},
            {"PAYMENT-REQUIRED": encode_header(payment_requirements(resource_url, error))},
        )


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), X402Handler)
    print(f"x402 simulation server listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
