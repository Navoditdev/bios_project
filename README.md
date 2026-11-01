# x402 Red/Blue: AI Agent Payment Guard

A local prototype for the **x402 Red/Blue** hackathon: guard an AI agent's
crypto wallet against overpayment and wrong-party offers, then run the same
attacks against other teams' guards.

The central security decision belongs on the payer side. The agent compares an
untrusted x402 offer with trusted spending policy **before the SDK can call the
signer**. A separate resource-server guard checks a submitted mock payment; it
does not replace payer-side protection.

## Current state

This repository provides:

- A deterministic payer policy for payment amount, recipient, network, asset,
  scheme, requested resource, offer shape, and rolling spend budgets.
- An in-memory ledger that atomically reserves spend before signing, then
  settles or releases that reservation after the mock response.
- A local x402 v2 flow using the official Python SDK and a placeholder signer.
- A browser demo for offer tampering and a seven-case decision-only attack suite.
- A CLI and `POST /evaluate` contract for repeatable local and peer guard
  evaluations.

There is no LLM-driven agent, private key, real signature, facilitator, or
on-chain settlement in this prototype. The local ledger resets when the server
process restarts and is not shared across processes. See
[HACKATHON_BRIEF.md](HACKATHON_BRIEF.md) for shared team context and
[CROSS_TEAM_TESTING.md](CROSS_TEAM_TESTING.md) for the peer testing contract.

## Policy under test

| Rule | Current demo setting |
| --- | --- |
| Maximum per payment | 10,000 atomic units (0.01 USDC), inclusive |
| Rolling 1-hour budget | 10,000 atomic units |
| Rolling 24-hour budget | 30,000 atomic units |
| Recipient | `0x209693Bc6afc0C5328bA36FaF03C514EF312287C` only |
| Network | Base Sepolia (`eip155:84532`) |
| Asset | Base Sepolia USDC (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`) |
| Scheme and offer shape | `exact`; exactly one accepted option |
| Invalid or ambiguous offers | Deny before signing |

The x402 offer cannot change the payer's policy. The budgets count pending
reservations as well as settled mock payments. The ledger is thread-safe within
one Python process, but it is not durable storage.

## Start the local demo

Requires Python 3.10 or later and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
.venv/bin/python server.py
```

With the server running, open:

- [Payment and attack demo](http://127.0.0.1:8402/demo) — inspect the mock
  payment flow, change offer fields, and run the seven decision-only cases.
- [Standalone attack-suite page](http://127.0.0.1:8402/cross-team) — run the
  shared cases and inspect each guard decision.

Keep the server terminal open while using either page. `127.0.0.1` is this
computer; no deployed site or wallet is required. The payment-flow demo uses a
mock signer and transfers no funds. The seven-case suite calls only the
`/evaluate` decision endpoint and never signs or submits payments.

For controlled peer testing on a network you manage, bind to a reachable
interface:

```sh
HOST=0.0.0.0 PORT=8402 .venv/bin/python server.py
```

The peer endpoint has no authentication. Do not expose it to the public
internet.

## Run from the command line

With the server running, inspect the x402 challenge without signing:

```sh
.venv/bin/python client.py
```

Run one mock payment flow:

```sh
.venv/bin/python mock_pay.py
```

Run the fixed suite directly against this project's payer policy (no server
required):

```sh
.venv/bin/python cross_team_test.py --local
```

Run it against another team's decision-only endpoint:

```sh
.venv/bin/python cross_team_test.py \
  --endpoint http://PEER_HOST:PORT/evaluate
```

The suite checks a valid baseline, overpayment, wrong-party recipient,
repeated valid calls, malformed amount, missing payment options, and ambiguous
options. The repeated-call scenario sends three valid 10,000-unit offers
against one fresh hourly budget; the expected result is `[true, false, false]`.
A peer response that denies every call does not pass that scenario. See
[CROSS_TEAM_TESTING.md](CROSS_TEAM_TESTING.md) for the request and response
contract.

## HTTP routes

| Route | Purpose |
| --- | --- |
| `GET /paid` | Returns an x402 v2 challenge or the mock resource |
| `GET /demo` | Payment-flow demo and decision-only case suite |
| `GET /demo/run` | Runs one mock payment-flow demonstration |
| `GET /cross-team` | Standalone shared attack-suite page |
| `GET /cross-team/scenarios` | Returns scenario metadata and offer fixtures |
| `POST /evaluate` | Evaluates an offer without signing or paying |
| `GET /health` | Local server health check |

`POST /evaluate` requires JSON with `scenario_id` and `offer`. It rejects
attempts to send policy settings. For `multiple_calls`, `offer` is an array; the
response includes aggregate `authorized` and one boolean per offer in
`call_results`. The endpoint evaluates against a fresh in-memory ledger for
each burst request.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | HTTP server bind address |
| `PORT` | `8402` | HTTP server port |
| `X402_PAY_TO` | Demo recipient above | Recipient advertised by `/paid` |
| `X402_AMOUNT` | `10000` | Amount advertised by `/paid`, in atomic units |

Changing the server's advertised offer does not change the independently
configured payer policy in `payer_agent.py`.

## Project layout

| File | Responsibility |
| --- | --- |
| `payer_agent.py` | Trusted payer policy, rolling budgets, and pre-signing gate |
| `payment_guard.py` | Resource-server mock checks and nonce replay protection |
| `server.py` | HTTP routes, mock resource server, and dry-run evaluation API |
| `mock_pay.py` | SDK payment flow and placeholder signer |
| `demo.html` | Combined payment-flow and decision-only browser demo |
| `cross_team_gui.html` | Standalone shared attack-suite interface |
| `attack_suite.py` | Stable shared scenario definitions and fixtures |
| `cross_team_test.py` | Local and peer suite runner |
| `client.py` | x402 v2 challenge parsing and validation |
| `test_*.py` | Unit and HTTP behavior tests |
| `HACKATHON_BRIEF.md` | Shared project and agent context |
| `CROSS_TEAM_TESTING.md` | Shared policy, scenarios, and peer API contract |

## Scope and limitations

The placeholder signer has no private key and returns bytes that are not a
valid ECDSA signature. The resource server accepts only the local mock marker;
it does not verify a real signature, contact a facilitator, or settle a
transaction. The mock receipt uses the transaction marker
`mock-not-settled`. No USDC is transferred, including on Base Sepolia.

The project demonstrates pre-signing policy control and dry-run guard
comparison. It is not production wallet protection. Production use would
require a real wallet boundary, durable shared budget storage, settlement
reconciliation, and authenticated peer evaluation.

## Tests

```sh
.venv/bin/python -m unittest -v
```
