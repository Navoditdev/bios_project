# Cross-team x402 guard testing

This workflow sends the same fixed x402 offer fixtures to this project's payer
guard or to another team's **decision-only** HTTP endpoint. It records the
expected and observed decisions, checks, reasons, errors, and timeouts. It does
not use the payment SDK, instantiate a wallet, call a signer, submit a payment,
or settle anything.

## Shared policy and scenarios

Each team configures trusted policy inside the guard it is testing. The offer
and request body are attacker-controlled test input and must never define or
raise that policy. Configure the guard for:

- Maximum amount: **10,000 atomic units per payment**, inclusive. Thus 10,000
  is allowed and 10,001 is denied.
- Approved recipient: **`0x209693Bc6afc0C5328bA36FaF03C514EF312287C`** only.
- Network: **`eip155:84532`** (Base Sepolia).
- Asset: **`0x036CbD53842c5426634e7929541eC2318f3dCF7e`** (Base Sepolia USDC).
- Scheme: **`exact`**, with exactly one accepted payment option.
- Malformed or missing payment fields fail closed.

The official cases are stable and intentionally prominent:

| Scenario ID | Offer | Expected |
| --- | --- | --- |
| `baseline_valid` | 10,000 to the approved recipient | Allow |
| `overpayment` | 10,001 to the approved recipient | Deny |
| `wrong_party` | 10,000 to `0x0000000000000000000000000000000000000001` | Deny |
| `multiple_calls` | Three valid 10,000-unit offers in one burst | First allow; later calls denied by rolling budget |

Supporting cases check `malformed_amount`, `missing_options`, and
`ambiguous_options` (multiple accepted payment options). A policy-violating
offer counts as an attack success only when the guard allows it. An offer
change that remains within policy is not an attack success.

The `multiple_calls` adversarial case sends an array of three valid offers in a
single `/evaluate` request. A compatible endpoint evaluates them in order
against one fresh rolling ledger and returns `authorized: false` if any call is
denied. Its `checks` names are prefixed with `call_1.`, `call_2.`, and so on;
`call_results` reports each individual decision. This models a burst without
signing or submitting payments. The default prototype budget permits the first
10,000-unit call and denies the next two within the rolling hour.

## Start this project's local server and runner

From the project directory, start the local HTTP server:

```sh
.venv/bin/python server.py
```

In another terminal, run the shared suite directly against this project's
configured local payer policy, with no HTTP payment flow:

```sh
.venv/bin/python cross_team_test.py --local
```

To evaluate against a peer's HTTP endpoint instead:

```sh
.venv/bin/python cross_team_test.py --endpoint http://127.0.0.1:8402/evaluate
```

Use a peer-provided endpoint URL in place of the example. The runner sends one
request per scenario, applies a five-second timeout by default, and exits with
status 1 if any expectation fails or the endpoint errors. Adjust the timeout
with `--timeout SECONDS`. The JSON report includes each expectation, actual
`allow`/`deny`, checks, reasons, errors/timeouts, and an attack-success
classification. The summary calls out baseline pass, overpayment block, and
wrong-party block separately. For `multiple_calls`, it also checks the exact
sequence `[true, false, false]`; denying every call does not count as a pass.

## Dry-run endpoint contract

This project's server exposes `POST /evaluate`. Other teams can implement the
same contract for their guard. Send JSON with exactly the scenario ID and offer:

```json
{
  "scenario_id": "overpayment",
  "offer": {
    "x402Version": 2,
    "resource": {"url": "https://cross-team.invalid/protected-resource"},
    "accepts": [{
      "scheme": "exact",
      "network": "eip155:84532",
      "amount": "10001",
      "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
    }]
  }
}
```

The endpoint compares the offer's resource URL with the shared fixture URL
`https://cross-team.invalid/protected-resource`. A valid decision responds with
HTTP 200 and this shape:

```json
{
  "scenario_id": "overpayment",
  "authorized": false,
  "checks": [
    {"name": "max_amount", "passed": false, "detail": "Offer exceeds the configured limit."}
  ],
  "reasons": ["Offer exceeds the configured limit."],
  "signing_attempted": false,
  "payment_submitted": false
}
```

`checks` is a list of objects; `reasons` is a list of strings. Every evaluation
must return both side-effect flags as `false`. The endpoint must not invoke a
signer, submit or retry a payment, or settle funds. Keep trusted policy in the
guard's own configuration. Requests containing extra keys, including policy
limits, are rejected with HTTP 400; malformed JSON also returns a clear 4xx
error. A malformed offer with the correct request envelope should return a
normal deny decision with checks and reasons.

The runner treats non-JSON responses, missing fields, mismatched scenario IDs,
non-boolean decisions/side-effect flags, and endpoints that claim to sign or
submit a payment as errors. Unavailable and timed-out endpoints are reported
per scenario instead of being counted as passes.

## Local tests

```sh
.venv/bin/python -m unittest -v
```

The cross-team suite uses an in-process guard for `--local`; the HTTP endpoint
is only needed to test peer-style request/response interoperability.
