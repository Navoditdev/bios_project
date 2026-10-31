# x402 Red/Blue — Shared Project Brief

This document is the shared context for the team and any coding agent working
on this project. Use it to keep implementation, demos, and explanations aligned
with the hackathon goal.

## Official hackathon statement

> x402 Red/Blue  
> Guard an AI agent's crypto wallet on the x402 payment protocol against
> overpayment and wrong-party attacks, then test other teams' guards.

## The goal in plain language

An AI agent may need to pay for a resource using x402. Before its wallet signs
or sends a payment, a **guard** should check that the payment is safe according
to the agent's intent and policy.

For example, the guard should catch a payment request that asks for more than
the agent meant to spend, or that directs funds to an untrusted recipient. The
agent must not treat an x402 offer from a remote service as its own spending
policy: the offer is input to inspect, not permission to spend.

The team should build a guard and then challenge it with attacks. We should also
be able to run comparable attacks against other teams' guards and explain what
each guard allowed or blocked.

## What Red and Blue mean here

- **Blue / defense:** Build the guard around the AI agent's payment flow. It
  checks the x402 offer and intended payment against the agent's policy before
  the wallet signs or submits anything.
- **Red / attack:** Try to make the guard approve a payment the agent should not
  make. The stated attack classes are overpayment and wrong-party payment.
- **Cross-team evaluation:** Run the same clear scenarios against our guard and
  other teams' guards, then record whether each attack was blocked and why.

“Red/Blue” describes the build-and-attack cycle. A “red-team lab” is just a
possible way to organize that work; it is not an additional official
requirement.

## Trust boundary: protect the payer

The key decision belongs on the **payer side**, before signing. The guard needs
to compare what the agent is about to authorize with trusted policy supplied by
the agent, its user, or its application. Relevant policy may include a spending
limit and approved recipients. Keep the scope tied to the official attack
classes; token and network checks can be useful supporting checks, but do not
lose sight of overpayment and wrong-party attacks.

A resource server may separately verify that an incoming payment matches the
server's price and destination. That is useful payment validation, but it does
not establish that the offer was safe for the payer's AI agent. Do not describe
server-side checks alone as protecting the agent's wallet.

## Current code versus the goal

The repository currently contains a **local x402 v2 mock prototype**:

- `server.py` sends an HTTP 402 challenge and serves a mock-paid resource.
- `mock_pay.py` connects the HTTP 402 parser, optional red-team challenge
  mutation, deterministic payer agent, x402 SDK, mock signer, and resource
  server in one flow.
- `payer_agent.py` applies trusted agent policy to the untrusted 402 offer
  before the SDK can call the signer. The current policy caps payment at
  `10000` atomic units and allowlists the demo recipient, Base Sepolia network,
  and USDC asset. Overpayment and wrong-party offers are denied before signing.
- The demo can alter the challenge's amount, recipient, asset, or network to
  check whether the payer guard blocks it and explain why.
- `payment_guard.py` remains a separate resource-server check. It validates
  received payments against the server's own configured terms; it is not the
  agent's wallet guard.

This is useful scaffolding for understanding the protocol and demonstrating
offer tampering. The deterministic policy check now sits on the payer side and
controls whether the x402 SDK reaches the signer. The signer is still a
placeholder; there is no private key, real signature verification, facilitator,
or on-chain settlement. The prototype demonstrates pre-signing policy control,
but does not yet provide protection for a real wallet.

## How to keep future work aligned

When planning or reviewing a change, ask:

1. Does this help the agent decide whether an x402 payment is within its own
   intent and policy before signing?
2. Does it address overpayment or wrong-party attacks, or make those attacks
   easier to test?
3. Can a teammate understand what the attacker changed, what policy the guard
   applied, and why the result was allow or deny?
4. Can the scenario be repeated against another team's guard in a comparable
   way?

Keep attack inputs untrusted. Keep the mock-versus-real boundary explicit. Avoid
claiming wallet protection unless the payer-side guard actually controls the
signing path and the demonstrated checks support that claim.

## Working vocabulary

- **Offer / challenge:** Payment requirements returned through x402, such as
  amount and payee.
- **Agent policy / intent:** Trusted constraints on what the agent may spend.
- **Guard:** The decision point that allows or blocks a payment before wallet
  authorization.
- **Overpayment attack:** An attempt to get the agent to authorize more than its
  intended or permitted amount.
- **Wrong-party attack:** An attempt to direct the payment to an unintended or
  untrusted recipient.
- **Test other teams' guards:** Apply agreed attack scenarios to another team's
  defense and record the decision and explanation.
