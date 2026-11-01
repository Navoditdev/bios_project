# NexVault | x402 Agent Payment Guard

A local prototype for the x402 Red/Blue challenge: guard an AI agent's crypto
wallet against overpayment and wrong-party attacks, then test other teams'
guards. NexVault checks offers on the payer side before signing, enforces
rolling spend budgets, and uses recent payment behavior to flag suspicious
request patterns.

> Guard an AI agent's crypto wallet on the x402 payment protocol against
> overpayment and wrong-party attacks, then test other teams' guards.

## Start here

Requires Python 3.10+ and uv. The project dependencies include the x402 Python
SDK and CPU-only XGBoost package.

    uv sync
    .venv/bin/python server.py

Open the single local demo:

- [Payment guard demo](http://127.0.0.1:8402/demo)

The page has two views:

1. **Payment demo** — run a mock x402 payment, alter offer fields, and inspect
   the eight-case policy and adversarial suite.
2. **Behavior attack lab** — run five behavior patterns and inspect decisions,
   risk scores, a radar profile, and a risk-over-attempt chart.

Keep the server terminal open while using the page. The demo uses a placeholder
signer and never transfers funds or creates a real signature. Both suites are
dry runs. The behavior lab uses a simulated clock, so the slow-drain case runs
without waiting.

The standalone cross-team suite is also available at
[http://127.0.0.1:8402/cross-team](http://127.0.0.1:8402/cross-team). The repo
contains the runner and endpoint contract; testing against another team's
guard requires that team's endpoint and a recorded run.

## How the guard works

Before the SDK can ask the signer to create a payment, the payer:

1. Scores the attempt using recent behavior, when the trained model is available.
2. Checks the offer against its own trusted policy.
3. Reserves the amount in the rolling spend ledger.
4. Only then allows the SDK to request a signature.

The model adds a behavioral signal; it does not replace the deterministic
limits. A high model score can block an otherwise policy-compliant payment.
If the model cannot be loaded, deterministic policy and budget checks still
run. The normal payment flow uses the model with persisted local history. The
single-offer cases in the shared policy suite focus on deterministic checks;
its repeated-call and small-payment-flood cases run with fresh model history
and budget state. These controls work together: fixed policy protects trusted
terms, budgets limit accumulated spend, and the behavior model can block
patterns that stay under those caps.

| Control | Demo setting |
| --- | --- |
| Maximum per payment | 10,000 atomic units (0.01 USDC) |
| Rolling hourly budget | 10,000 atomic units |
| Rolling daily budget | 30,000 atomic units |
| Recipient | 0x209693Bc6afc0C5328bA36FaF03C514EF312287C |
| Network | Base Sepolia, eip155:84532 |
| Asset | Base Sepolia USDC, 0x036CbD53842c5426634e7929541eC2318f3dCF7e |
| Payment scheme | exact, with one accepted option |

The offer cannot change these payer-owned settings.
USDC uses six decimal places here; amounts in the offer and ledger are atomic
units.

## Behavior attack lab

The lab replays fixed request sequences through the same XGBoost scorer, payer
policy, and ledger used by the prototype. It reports per-attempt allow/deny
decisions and identifies whether the model, payer policy, or budget blocked an
attempt.

| Pattern | What it exercises |
| --- | --- |
| Small-payment flood | Rapid 1,000-unit calls totaling less than the hourly budget |
| Near-cap burst | Repeated individually valid payments near the per-payment limit |
| Policy probing | Invalid and over-limit requests followed by repeated attempts |
| Resource churn | Small payments across new resource origins |
| Slow drain | Near-cap requests spaced across the day |

Each run uses fresh in-memory history and a simulated clock. The radar chart
shows peak normalized signals for request rate, hourly and daily spend,
near-cap use, origin churn, denial streak, repeated amounts, and request
spacing. The line chart shows model risk per attempt and the deny threshold.

The model was trained on synthetic sessions. Its scores and training metrics
are demonstrations, not real-world fraud probabilities or evidence of
production detection quality. Training, calibration, and held-out evaluation
sessions are separated by session ID, but they share the same synthetic data
generator. The recorded results show that the model learned these generated
patterns; they do not establish performance against real attackers.

The mock payment flow keeps its local event history in
`data/behavior_events.sqlite3`. It records timestamps, amounts, origin hosts, and
outcomes; it does not store resource URL paths or query strings. Generated
training data and local event history are ignored by Git. History is grouped
under a configured `agent_id`; the current demo uses one local profile and does
not bind that profile to a cryptographically verified wallet identity or
fingerprint.

## Run from the command line

Inspect the x402 challenge without signing:

    .venv/bin/python client.py

Run the mock payment flow (start the server first):

    .venv/bin/python mock_pay.py

### Live terminal demo for judges

From the project directory, run the same eight adversarial cases used by the
payment dashboard directly against the Python payer guard. **No server or
browser is required** (run `uv sync` once to install dependencies):

```bash
.venv/bin/python cross_team_test.py --local --demo
```

The runner evaluates a valid baseline, overpayment, wrong recipient, repeated
payments, a small-payment flood, malformed amounts, missing options, and
ambiguous options. It prints each case as it finishes, showing the expected
and actual ALLOW/DENY decisions, the blocking checks, and the call sequence
for burst attacks. A **PASS** means the guard behaved as expected: allowing
the baseline or denying an attack. A blocking policy check is expected for
a denied attack.

For a deeper demonstration with every check and a saved evidence report:

```bash
.venv/bin/python cross_team_test.py \
  --local --demo --verbose \
  --report /tmp/nexvault-adversarial-report.json
```

The report contains the full decisions, check details, denial reasons, and
per-call results. These are fresh evaluations of the guard implementation,
not prerecorded dashboard output. Each burst gets fresh in-memory history
and budget state; the flood case uses the bundled XGBoost model. Missing
model detection, unexpected decisions, or endpoint errors fail the suite.
The command exits with code `0` when all cases pass and `1` on failure.
These are decision-only tests: no signer is created and no funds are sent.

To demonstrate the running server's `/evaluate` API instead, start
`.venv/bin/python server.py` in another terminal, then run:

```bash
.venv/bin/python cross_team_test.py --endpoint http://127.0.0.1:8402/evaluate --demo
```

You can replace that endpoint with another team's compatible evaluation URL.
Without `--demo`, the runner retains its full JSON output and text summary:

```bash
.venv/bin/python cross_team_test.py --local
```

Regenerate the synthetic training data and retrain the model:

    .venv/bin/python train_behavior_model.py

Training creates benign sessions and five attack patterns. It splits complete
sessions between training, validation, threshold calibration, and held-out
evaluation. The generated CSV is stored under the ignored data directory;
model metrics and threshold are recorded in models/payment_risk.json.

## HTTP routes

| Route | Purpose |
| --- | --- |
| GET /demo | Combined payment and behavior demo |
| GET /demo/run | Run one mock payment-flow demonstration |
| GET /paid | Return an x402 challenge or the mock resource |
| GET /cross-team | Standalone shared attack-suite page |
| GET /cross-team/scenarios | Return shared scenario fixtures |
| POST /evaluate | Evaluate shared cases without signing or paying |
| GET /behavior-lab/scenarios | List the fixed behavior profiles |
| POST /behavior-lab/run | Run one behavior profile through payer checks |
| GET /health | Local server health |

The shared decision endpoint accepts only a scenario ID and offer. For the
multiple-call and small-payment-flood cases, the offer is an array; the
response includes aggregate authorization and one result per call. Each burst
uses fresh in-memory history and budget state.

The behavior-run endpoint accepts only a fixed scenario ID. It does not accept
caller-supplied offers, policy settings, or model parameters.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| HOST | 127.0.0.1 | Server bind address |
| PORT | 8402 | Server port |
| X402_PAY_TO | Demo recipient above | Recipient advertised by /paid |
| X402_AMOUNT | 10000 | Amount advertised by /paid, in atomic units |

For peer testing on a network you manage, you can bind to a reachable
interface:

    HOST=0.0.0.0 PORT=8402 .venv/bin/python server.py

The peer endpoint has no authentication; do not expose it to the public
internet.

## Project map

| File | Purpose |
| --- | --- |
| payer_agent.py | Trusted policy, rolling budgets, and pre-signing gate |
| behavior_risk.py | SQLite behavior history, features, and XGBoost scoring |
| behavior_lab.py | Fixed behavior profiles and simulated-clock runs |
| synthetic_behavior_data.py | Labeled synthetic session generator |
| train_behavior_model.py | Grouped training, threshold calibration, and evaluation |
| models/payment_risk.ubj | Trained prototype model |
| server.py | Local HTTP server and demo APIs |
| mock_pay.py | SDK mock payment flow and placeholder signer |
| payment_guard.py | Resource-server checks and nonce replay protection |
| demo.html | Combined local demo interface |
| cross_team_gui.html | Standalone shared attack-suite interface |
| attack_suite.py | Shared policy and adversarial fixtures |
| cross_team_test.py | Local and peer suite runner |
| CROSS_TEAM_TESTING.md | Peer testing contract |
| HACKATHON_BRIEF.md | Shared project context |
| test_*.py | Policy, protocol, suite, and terminal-demo tests |

## Limitations

This is not production wallet protection. The signer is a placeholder, the
resource server accepts only a local mock marker, and no facilitator or
blockchain settlement is involved.

The spend ledger is in process memory and resets when the server restarts. The
mock payer's behavior history is stored locally in SQLite, but is not shared
transactionally across signer processes. Production use would need a durable
shared ledger, settlement reconciliation, authenticated service boundaries,
and model evaluation on reviewed real-world data.

## Tests

Run the unit and HTTP behavior suite with:

    .venv/bin/python -m unittest -v
