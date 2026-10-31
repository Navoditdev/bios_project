# AI Agent x402 Wallet Guard — Hackathon Project

## Project context for coding agents

For the team's shared statement of the goal, threat boundary, and current
prototype status, see [HACKATHON_BRIEF.md](HACKATHON_BRIEF.md).

This project explores how to protect an AI agent's crypto wallet when it pays
for resources using the x402 payment protocol. The target threats are payments
that exceed the agent's intended price and payments sent to the wrong recipient
(or use the wrong token or network). The hackathon also aims to test and compare
other teams' payment guards with adversarial offers.

Think of the project as a **payment-guard red-team lab**: construct realistic
x402 payment flows, apply attacks to the offer or payment, run a guard, and make
the outcome and reason understandable. The eventual security decision should
be made on the payer side, against the agent's spending policy, before the
agent signs or submits a payment.

### Trust boundary

There are two different places a guard can sit:

- **Payer-side guard (the project goal):** checks an untrusted x402 offer
  against the agent's policy before signing. Examples include a maximum amount,
  an approved recipient, and an approved token and network.
- **Resource-server guard (also retained in this prototype):** checks a
  submitted payment against the server's own configured offer before serving a
  resource.

These checks solve related but different problems. A server checking that it
received the amount it requested does not prove that the offer was safe for the
AI agent to accept. Keep this distinction clear when extending the code or
describing results.

### Current prototype

The Python prototype implements a local x402 v2 HTTP round trip with a payer-side
decision gate:

1. The server returns HTTP 402 with a `PAYMENT-REQUIRED` challenge.
2. `client.py` parses the challenge. The local red-team demo can alter amount,
   recipient (`payTo`), token asset, or network before the payer agent evaluates
   the offer.
3. `DeterministicPaymentAgent` compares the offer with its own trusted policy.
   A denied offer never reaches the x402 SDK signer and no payment retry is sent.
4. If payer policy allows the offer, the x402 SDK builds an EIP-3009 payload
   using the clearly fake `MockEvmSigner`.
5. The resource server's separate `PaymentGuard` checks the payment it receives
   against its own configured terms. This server-side check does not replace
   payer-side wallet protection.
6. The demo shows the payer decision, whether signing occurred, the retry, and
   any server-side result.

Relevant files:

- `payment_guard.py` — explicit server-side authorization checks and decision
  details.
- `payer_agent.py` — deterministic payer policy that gates the SDK signing call.
- `server.py` — local x402 resource server and interactive red-team demo.
- `mock_pay.py` — official x402 SDK flow with a fake signer and offer-tampering
  scenarios.
- `client.py` — parses and structurally validates the x402 challenge.
- `test_payer_agent.py`, `test_payment_guard.py`, `test_server.py` — tests for
  the payer policy, server guard, and local protocol flow.

### Guidance for future changes

- Keep payer policy checks distinct from server-side payment verification.
  The central product direction is to prevent an agent from signing a payment
  that violates its own policy, even if the offer is validly formatted.
- Treat payment challenges and all fields supplied by remote services as
  untrusted input. Do not let a challenge itself define the agent's limits or
  trusted recipients.
- Make attacks and guard decisions observable: show what the agent was offered,
  what policy applied, which checks passed or failed, and whether signing or
  payment submission was stopped.
- Design the red-team interface so different teams' guards can be evaluated
  against the same normal and adversarial scenarios, with comparable outcomes.
- Preserve the local mock's safety boundary. It uses no private key, does not
  verify a real ECDSA signature, and does not settle a transaction. Do not
  present it as wallet protection or production payment verification.

## Local x402 prototype

This is a local x402 v2 HTTP prototype. The resource server is Python, and the
mock payer uses the official x402 Python SDK (`x402[evm]` 2.26.0). `/paid`
returns `402 Payment Required` with `PAYMENT-REQUIRED`; the mock payer parses
that challenge, creates an SDK payment payload, and retries with
`PAYMENT-SIGNATURE`.

## Run

```sh
uv sync
.venv/bin/python server.py
```

Then, from another terminal:

```sh
curl -i http://127.0.0.1:8402/paid
```

To make a client request and parse the x402 v2 challenge:

```sh
.venv/bin/python client.py
```

The client prints the decoded `PAYMENT-REQUIRED` object and its accepted
payment option. It does not sign or submit a payment.

To run the full SDK mock payment (server must be running in another terminal):

```sh
.venv/bin/python mock_pay.py
```

For the red-team GUI, open [http://127.0.0.1:8402/demo](http://127.0.0.1:8402/demo).
Select a field, edit its replacement value, and click **Run this scenario**.
Try the baseline first, then change the amount, recipient, asset, and network.
The page reports whether the payer guard allowed the offer, whether the mock
signer was called, whether a retry was sent, the reason for a denial, and the
resource server's separate result. A plain-language summary appears above the
collapsible **Technical details (JSON)** section. `/health` reports whether the
server guard is active.

**Local demo:** [http://127.0.0.1:8402/demo](http://127.0.0.1:8402/demo)

## How the mock signing works

The official SDK's `ExactEvmScheme` constructs an EIP-3009
`TransferWithAuthorization` using the advertised payer, recipient, amount,
validity window, nonce, and Base Sepolia USDC EIP-712 domain. It calls the
`ClientEvmSigner.sign_typed_data(domain, types, primary_type, message)` method.
`MockEvmSigner` implements that SDK interface, records the typed-data request,
and returns the obvious placeholder bytes `MOCK-ONLY-NOT-A-REAL-ECDSA-SIGNATURE`.
There is no private key and no real cryptographic signature. The SDK encodes
the resulting payload into the standard Base64 `PAYMENT-SIGNATURE` header.

The payer agent runs before `ExactEvmScheme` is constructed. Its default trusted
policy allows at most `10000` atomic units, the configured demo recipient, Base
Sepolia (`eip155:84532`), and the Base Sepolia USDC asset. The 402 offer cannot
change these limits. A deterministic policy denial means zero signer calls and
no retry request.

The local server checks that the terms match and that the signature field is
exactly the mock marker. This only verifies that the SDK created and transported
the expected shape. It does not verify an ECDSA signature or contact a
facilitator. The response labels the transaction `mock-not-settled`; no USDC is
transferred, including on Base Sepolia.

`mock_pay.py` connects `client.py`'s HTTP 402 parser, a red-team challenge
mutation, `payer_agent.py`, the official x402 SDK mock signer, and the resource
server in one request flow. The mutation happens after parsing and before payer
policy evaluation. This simulates an attacker changing the 402 requirements in
transit; it does not modify the server's original offer.

`payer_agent.py` is the wallet-protection decision point in this prototype. Its
policy is configured separately from the HTTP offer and is evaluated before
signing. `payment_guard.py` remains a resource-server validation example: it
binds the received payload to the requested resource and checks the server's
scheme/network/token/amount/payee, payer allowlist, authorization time window,
nonce format/reuse, and mock signature marker. Its in-memory replay list clears
when the server restarts. Do not describe this server-side validation as payer
wallet protection.

The challenge advertises Base Sepolia USDC for `0.01 USDC` (`10000` atomic
units). Set `X402_PAY_TO` to a receiving address and `X402_AMOUNT` to change
the advertised terms. `HOST` and `PORT` control the listener.

## Scope

The protocol headers and payload shape follow the x402 v2 HTTP transport.
Mock signature checking and settlement are not real payment verification.
This prototype is for local protocol experiments only and must not protect real
resources.

For a real x402 integration, replace the simulation check with the official
x402 server SDK and a supported facilitator configured for the chosen network.

## Test

```sh
.venv/bin/python -m unittest -v
```
