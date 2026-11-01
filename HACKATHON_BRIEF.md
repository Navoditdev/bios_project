# x402 Red/Blue — Shared Project Brief

This brief keeps the team's implementation, demos, and coding agents aligned
with the hackathon goal.

## Official statement

> **x402 Red/Blue**
>
> Guard an AI agent's crypto wallet on the x402 payment protocol against
> overpayment and wrong-party attacks, then test other teams' guards.

## Goal

An AI agent may need to pay for a resource using x402. Before its wallet signs
or submits a payment, a payer-side guard checks the offer against trusted
spending policy. It should prevent overpayment and payment to an unintended
recipient.

The team also needs to attack its own guard and run comparable cases against
other teams' guards. The offer is untrusted input; it must not set or expand
the agent's policy.

## Trust boundary

The security decision belongs on the payer side, before signing. A resource
server may verify that it received the payment it requested, but that does not
show the offer was safe for the payer's agent. Keep payer authorization
separate from server-side payment validation.

## Current implementation

The repository contains a local x402 v2 mock prototype with:

- `payer_agent.py`: deterministic checks against an independently configured
  maximum amount, recipient allowlist, network, asset, scheme, requested
  resource, and offer shape. A thread-safe in-memory ledger reserves spend
  before signing and enforces rolling hourly and daily budgets.
- `behavior_risk.py`: extracts recent payment-pattern features from local
  SQLite history and applies the bundled XGBoost behavior-risk model before
  signing. The demo stores origin hosts, amounts, timestamps, and outcomes, not
  resource URL paths or query strings.
- `behavior_lab.py`, `synthetic_behavior_data.py`, and
  `train_behavior_model.py`: run five simulated attack profiles and train the
  prototype model from labeled synthetic sessions.
- `mock_pay.py` and `demo.html`: the official x402 SDK creates a payload using
  a placeholder signer; the demo can tamper with selected offer fields and
  display the result. A successful mock response settles the reservation;
  definite payment denial releases it.
- `payment_guard.py`: separate resource-server validation, including terms,
  time window, and in-process nonce replay checks.
- `attack_suite.py` and `cross_team_test.py`: shared fixtures and a CLI runner
  for local or peer HTTP dry-run evaluation.
- `server.py` and `cross_team_gui.html`: the resource server, decision-only
  `POST /evaluate` endpoint, and shared attack-suite GUI.
- `CROSS_TEAM_TESTING.md`: the expected shared policy, scenarios, and peer API
  contract.

The shared suite includes a valid baseline, overpayment, wrong-party, repeated
valid calls, malformed amount, missing-options, and ambiguous-options cases.
Its dry-run endpoint returns decisions only; it never signs or submits a
payment.

## Current limits

The behavior model and its evaluation data are synthetic; metrics do not
establish real-world detection quality. The local demo uses one configured
`agent_id`, not a cryptographically verified agent identity or fingerprint.
The project does not currently include an LLM-driven agent. The signer is a
placeholder; the project does not use a private key, verify a real ECDSA
signature, contact a facilitator, or settle an on-chain payment. A peer
endpoint must be supplied to record an actual cross-team run. The spend ledger
is process-local and resets on restart; it is not durable or shared across
multiple signer processes.

Do not describe the mock prototype as production wallet protection. Describe it
as a payer-side policy gate and cross-team dry-run harness under development.

## Direction for future work

- Keep trusted policy independent from the x402 challenge and any model output.
- Keep denial before the signer, and make the reason and side effects visible.
- Prioritize the official overpayment and wrong-party attack classes.
- Use the shared suite for comparable peer testing and report actual results.
- Preserve the mock-versus-real boundary in demos and presentations.
