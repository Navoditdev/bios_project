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

from payment_guard import GuardConfig, PaymentGuard
from payer_agent import DeterministicPaymentAgent
from attack_suite import offer_for_scenario, scenario_catalog


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


DEMO_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Local x402 payment guard demo</title>
  <style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; background: #f4f7fb; color: #152238; }
    body { max-width: 920px; margin: 36px auto; padding: 0 20px; }
    h1 { margin-bottom: 8px; }
    .note { color: #5a6780; line-height: 1.5; }
    .steps { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 24px 0; }
    .step, .panel { background: white; border: 1px solid #dce4ef; border-radius: 12px; padding: 16px; }
    .step b { display: block; color: #2463eb; margin-bottom: 6px; }
    .summary { background: white; border: 1px solid #dce4ef; border-left: 6px solid #7d8aa0; border-radius: 12px; margin: 12px 0 20px; padding: 18px 20px; }
    .summary.allowed { border-left-color: #16834b; }
    .summary.blocked { border-left-color: #c63c3c; }
    .summary h3 { margin: 0 0 10px; }
    .summary p { line-height: 1.5; margin: 6px 0; }
    .summary ul { line-height: 1.5; margin: 6px 0; padding-left: 22px; }
    details { margin-top: 14px; }
    button { background: #2463eb; border: 0; border-radius: 8px; color: white; cursor: pointer; font-size: 16px; padding: 12px 18px; }
    button:disabled { cursor: wait; opacity: .65; }
    #status { margin-left: 12px; color: #50617a; }
    pre { overflow: auto; max-height: 560px; background: #111827; border-radius: 10px; color: #e5eefc; padding: 18px; line-height: 1.45; }
    .warning { border-left: 4px solid #ed9b21; padding: 10px 14px; background: #fff7e8; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>Local x402 payment guard</h1>
  <p class="note">Run the normal flow, or act as a red team member and alter one field in the HTTP 402 offer. The deterministic payer agent checks its own policy before it lets the x402 SDK call the signer.</p>
  <div class="warning"><b>Mock mode:</b> the payer guard is real control flow, but the wallet is a mock signer that returns a placeholder. No private key or funds are used.</div>
  <section class="steps" aria-label="Payer-side decision order">
    <div class="step"><b>1 · Parse offer</b><code>client.py</code> decodes the HTTP 402 requirements.</div>
    <div class="step"><b>2 · Payer policy</b>Agent checks the offer against its own trusted limits and allowlists.</div>
    <div class="step"><b>3 · Sign only after ALLOW</b>Only then does the x402 SDK call the mock signer.</div>
    <div class="step"><b>4 · Retry</b>A denied offer never sends a payment retry.</div>
    <div class="step"><b>5 · Optional server validation</b>The resource server checks a retry only if the payer sent one.</div>
  </section>
  <p class="note"><b>Red-team injection point:</b> an attack may alter the parsed offer after step 1 and before step 2. It cannot change the payer's trusted policy.</p>
  <section class="panel">
    <label for="attack"><b>Red-team field</b></label>
    <select id="attack">
      <option value="">No tampering (baseline)</option>
      <option value="amount">Change amount</option>
      <option value="recipient">Change recipient (payTo)</option>
      <option value="asset">Change token asset</option>
      <option value="network">Change network</option>
    </select>
    <label for="value"><b>Replacement value</b></label>
    <input id="value" value="20000" aria-label="Replacement payment requirement value">
    <button id="run">Run this scenario</button><span id="status" role="status"></span>
    <p class="note">Examples: amount <code>20000</code>; recipient or asset a different 0x address; network <code>eip155:8453</code>.</p>
  </section>
  <h2>What happened</h2>
  <section id="summary" class="summary" aria-live="polite">
    <h3>Ready to run</h3>
    <p>Choose a scenario above. This summary will explain the agent's decision in plain language.</p>
  </section>
  <details>
    <summary>Technical details (JSON)</summary>
    <pre id="output">Run a scenario to see the parsed offer, payer policy checks, signer input, retry, and server-side result.</pre>
  </details>
  <script>
    const button = document.querySelector('#run');
    const attack = document.querySelector('#attack');
    const value = document.querySelector('#value');
    const examples = { amount: '20000', recipient: '0x0000000000000000000000000000000000000001', asset: '0x0000000000000000000000000000000000000002', network: 'eip155:8453' };
    attack.addEventListener('change', () => { if (examples[attack.value]) value.value = examples[attack.value]; });
    function renderSummary(result) {
      const box = document.querySelector('#summary');
      box.replaceChildren();
      const decision = result.payer_guard_decision;
      if (!decision) {
        box.className = 'summary blocked';
        const title = document.createElement('h3');
        title.textContent = 'The flow could not complete';
        box.append(title);
        const message = document.createElement('p');
        message.textContent = result.error || 'The server did not return a payer decision.';
        box.append(message);
        return;
      }

      const changed = result.scenario && result.scenario.field;
      const allowed = decision.authorized;
      box.className = 'summary ' + (allowed ? 'allowed' : 'blocked');
      const heading = document.createElement('h3');
      heading.textContent = changed
        ? (result.red_team_result.succeeded
          ? 'Attack succeeded: policy-violating offer reached the signer'
          : (allowed ? 'Offer change is policy-compliant; attack not successful' : 'Red-team offer was blocked before signing'))
        : (allowed ? 'Baseline offer was allowed' : 'Agent policy blocked the offer');
      box.append(heading);

      const scenario = document.createElement('p');
      scenario.textContent = changed
        ? 'Red team changed ' + changed + ' to ' + result.scenario.value + '.'
        : 'No offer field was changed.';
      box.append(scenario);

      const decisionLine = document.createElement('p');
      decisionLine.textContent = allowed
        ? 'The offer is within the agent’s trusted policy.'
        : 'The agent denied the offer using policy stored on the payer side.';
      box.append(decisionLine);

      const signerLine = document.createElement('p');
      signerLine.textContent = result.signing_attempted
        ? 'Signer: called ' + result.signer_call_count + ' time(s) (mock only).'
        : 'Signer: not called. The offer was stopped before signing.';
      box.append(signerLine);

      const retryLine = document.createElement('p');
      retryLine.textContent = result.retry_sent
        ? 'Payment retry: sent; resource server replied ' + result.flow[5].result + '.'
        : 'Payment retry: not sent.';
      box.append(retryLine);

      const serverLine = document.createElement('p');
      serverLine.textContent = result.server_guard_evaluated
        ? 'Separate resource-server guard: ' + result.flow[6].result + '.'
        : 'Separate resource-server guard: not reached.';
      box.append(serverLine);

      if (decision.reasons && decision.reasons.length) {
        const why = document.createElement('p');
        why.textContent = 'Why the payer guard denied it:';
        box.append(why);
        const list = document.createElement('ul');
        for (const reason of decision.reasons) {
          const item = document.createElement('li');
          item.textContent = reason;
          list.append(item);
        }
        box.append(list);
      }
      if (changed && result.red_team_result) {
        const attack = document.createElement('p');
        attack.textContent = 'Red-team result: ' + result.red_team_result.summary;
        box.append(attack);
      }
      const caveat = document.createElement('p');
      caveat.className = 'note';
      caveat.textContent = 'The signer is a placeholder. This demo makes no real wallet signature and transfers no funds.';
      box.append(caveat);
    }
    button.addEventListener('click', async () => {
      button.disabled = true;
      document.querySelector('#status').textContent = 'Running local SDK flow…';
      try {
        const params = new URLSearchParams();
        if (attack.value) { params.set('attack', attack.value); params.set('value', value.value); }
        const response = await fetch('/demo/run?' + params.toString());
        const result = await response.json();
        renderSummary(result);
        document.querySelector('#output').textContent = JSON.stringify(result, null, 2);
        const allowed = result.payer_guard_decision && result.payer_guard_decision.authorized;
        document.querySelector('#status').textContent = allowed ? 'Payer guard ALLOWED' : (result.payer_guard_decision ? 'Payer guard DENIED' : 'Flow failed');
      } catch (error) {
        document.querySelector('#status').textContent = String(error);
      } finally {
        button.disabled = false;
      }
    });
  </script>
</body>
</html>"""


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

    def send_json(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
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

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/cross-team":
            gui_path = Path(__file__).with_name("cross_team_gui.html")
            self.send_html(gui_path.read_text(encoding="utf-8"))
            return
        if parsed.path == "/cross-team/scenarios":
            scenarios = scenario_catalog()
            for scenario in scenarios:
                scenario["offer"] = offer_for_scenario(scenario["scenario_id"])
            self.send_json(200, {"scenarios": scenarios})
            return
        if parsed.path == "/demo":
            self.send_html(DEMO_HTML)
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
            self.send_json(
                # HTTP 200 here means the test run completed. The nested
                # resource response below separately shows whether /paid
                # allowed (200) or denied (402) the mock payment.
                200,
                {
                    "scenario": signer.attack or {"field": None, "value": None},
                    "red_team_result": (
                        {
                            "succeeded": bool(
                                signer.attack
                                and signer.payer_decision
                                and not signer.payer_decision["authorized"]
                                and signer.signing_attempted
                            ),
                            "policy_violated": bool(
                                signer.payer_decision and not signer.payer_decision["authorized"]
                            ),
                            "summary": (
                                "A policy-violating offer reached the signer. The attack succeeded at the wallet boundary."
                                if signer.payer_decision and not signer.payer_decision["authorized"] and signer.signing_attempted
                                else (
                                    "The offer change still satisfies payer policy; the attack was not successful."
                                    if signer.payer_decision and signer.payer_decision["authorized"]
                                    else "The payer guard denied the offer before signing. The attack was not successful."
                                )
                            ),
                            "why": signer.payer_decision["reasons"] if signer.payer_decision and not signer.payer_decision["authorized"] else [],
                        }
                        if signer.attack
                        else {"succeeded": False, "summary": "Baseline run: no red-team modification was attempted.", "why": []}
                    ),
                    "flow": [
                        {"step": 1, "event": "GET /paid without payment", "result": "HTTP 402 Payment Required"},
                        {"step": 2, "event": "client.parse_payment_requirements", "result": "Decoded and structurally checked the 402 offer"},
                        {"step": 3, "event": "Red-team challenge tampering", "result": "No change" if not signer.attack else f"Changed {signer.attack['field']} to {signer.attack['value']}"},
                        {"step": 4, "event": "DeterministicPaymentAgent policy", "result": "ALLOW" if signer.payer_decision and signer.payer_decision["authorized"] else "DENY"},
                        {"step": 5, "event": "SDK signer invocation", "result": "Called MockEvmSigner.sign_typed_data" if signer.signing_attempted else "BLOCKED; signer was not called"},
                        {"step": 6, "event": "Payment retry", "result": f"HTTP {status}" if signer.retry_sent else "NOT SENT"},
                        {"step": 7, "event": "Resource server guard", "result": ("ALLOW" if decision and decision.authorized else "DENY") if signer.server_guard_evaluated else "NOT REACHED"},
                    ],
                    "original_parsed_requirements": signer.parsed_requirements,
                    "requirements_evaluated_by_payer": signer.modified_requirements,
                    "requirements_received_by_sdk": signer.modified_requirements if signer.signing_attempted else None,
                    "payer_guard_decision": signer.payer_decision,
                    "signing_attempted": signer.signing_attempted,
                    "signer_call_count": signer.sign_calls,
                    "retry_sent": signer.retry_sent,
                    "signing_request": signer.last_signing_request,
                    "mock_signature": MOCK_SIGNATURE_HEX,
                    "submitted_payload": signer.last_payment_payload,
                    "server_guard_evaluated": signer.server_guard_evaluated,
                    "server_guard_decision": decision.to_dict() if signer.server_guard_evaluated and decision else None,
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
        decision = CROSS_TEAM_AGENT.evaluate(payload["offer"], CROSS_TEAM_RESOURCE_URL)
        self.send_json(
            200,
            {
                "scenario_id": scenario_id,
                "authorized": decision.authorized,
                "checks": [
                    {"name": check.name, "passed": check.passed, "detail": check.detail}
                    for check in decision.checks
                ],
                "reasons": decision.reasons,
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
