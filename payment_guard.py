"""A small, heavily commented authorization guard for the local x402 mock.

This is a teaching example, not a production payment verifier. In particular,
it can check payment terms and a mock marker, but it cannot prove that an EVM
wallet signed an EIP-712 message. Real deployments must use the x402 server SDK
and a real facilitator or a verified local settlement implementation.
"""

from __future__ import annotations

import hmac
import re
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any


_NONCE_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class GuardConfig:
    """The one payment option this local demo is willing to authorize."""

    scheme: str
    network: str
    amount: str
    asset: str
    pay_to: str
    mock_signature: str
    allowed_payers: frozenset[str]
    max_timeout_seconds: int = 60


@dataclass(frozen=True)
class Check:
    """One named authorization check, shown by the localhost demo page."""

    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class GuardDecision:
    """The full result from one guard evaluation."""

    authorized: bool
    checks: tuple[Check, ...]

    @property
    def reasons(self) -> list[str]:
        """Human-readable reasons for every failed check."""
        return [check.detail for check in self.checks if not check.passed]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-safe detail for logs and the demo UI."""
        return {
            "authorized": self.authorized,
            "checks": [asdict(check) for check in self.checks],
            "reasons": self.reasons,
            "mode": "mock-only; no signature verification or settlement",
        }


class PaymentGuard:
    """Check that a submitted x402 payment matches the demo's offer.

    The guard is purposely explicit: it checks each fact and reports the
    result. A lock protects the in-memory replay list because the HTTP server
    uses multiple request threads.
    """

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self._used_nonces: set[str] = set()
        self._nonce_lock = threading.Lock()
        self._last_decision: GuardDecision | None = None

    @property
    def last_decision(self) -> GuardDecision | None:
        """Most recent decision, for the single-user localhost demo display."""
        return self._last_decision

    def authorize(self, payment: Any, resource_url: str) -> GuardDecision:
        """Return ALLOW only when every mock authorization check passes.

        The order of checks matters. We first check the envelope and every
        advertised term, then time/nonce/payer rules, and finally the exact
        mock signature marker. We reserve the nonce only after all those
        checks pass so rejected requests do not consume a valid nonce.
        """
        checks: list[Check] = []

        # Small helpers keep the checks readable and make the UI explain each
        # decision without exposing private implementation details.
        def check(name: str, passed: bool, ok: str, failed: str) -> None:
            checks.append(Check(name=name, passed=passed, detail=ok if passed else failed))

        # A payment payload is untrusted input. Check container types before
        # looking up nested values so malformed JSON is a clean DENY, not a
        # server exception.
        is_object = isinstance(payment, dict)
        check(
            "payload_object",
            is_object,
            "Payload is a JSON object.",
            "Payload must be a JSON object.",
        )
        payment = payment if is_object else {}

        check(
            "x402_version",
            payment.get("x402Version") == 2,
            "Payload uses x402 v2.",
            "Payload must use x402 version 2.",
        )

        # Bind the payment to this exact resource. A payment for another URL
        # must not be replayable against /paid.
        resource = payment.get("resource")
        resource = resource if isinstance(resource, dict) else {}
        check(
            "resource_url",
            resource.get("url") == resource_url,
            "Payment is bound to this URL.",
            "Payment resource URL does not match this request.",
        )

        # Compare the selected payment option with what the server advertised.
        # These values control where, how much, and on which token/network money
        # would move if this were real.
        accepted = payment.get("accepted")
        accepted = accepted if isinstance(accepted, dict) else {}
        expected_terms = {
            "scheme": self.config.scheme,
            "network": self.config.network,
            "amount": self.config.amount,
            "asset": self.config.asset,
            "payTo": self.config.pay_to,
        }
        for field_name, expected in expected_terms.items():
            passed = accepted.get(field_name) == expected
            check(
                f"accepted_{field_name}",
                passed,
                f"Accepted {field_name} matches the offer.",
                f"Accepted {field_name} does not match the offer.",
            )

        # The scheme-specific payload holds the transfer authorization and
        # signature. Validate it as untrusted data too.
        payload = payment.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        authorization = payload.get("authorization")
        authorization = authorization if isinstance(authorization, dict) else {}

        payer = authorization.get("from")
        allowed_payers = {address.lower() for address in self.config.allowed_payers}
        payer_is_allowed = isinstance(payer, str) and payer.lower() in allowed_payers
        check(
            "payer_allowlist",
            payer_is_allowed,
            "Payer is on the local demo allowlist.",
            "Payer is not on the local demo allowlist.",
        )

        destination = authorization.get("to")
        destination_matches = (
            isinstance(destination, str) and destination.lower() == self.config.pay_to.lower()
        )
        check(
            "authorization_destination",
            destination_matches,
            "Authorization destination matches payTo.",
            "Authorization destination does not match payTo.",
        )

        # Avoid numeric coercion from arbitrary objects; only decimal strings
        # and integers are accepted in the authorization body.
        value = authorization.get("value")
        value_matches = (
            isinstance(value, (str, int))
            and not isinstance(value, bool)
            and str(value) == self.config.amount
        )
        check(
            "authorization_amount",
            value_matches,
            "Authorization amount exactly matches the price.",
            "Authorization amount does not exactly match the price.",
        )

        # EIP-3009 authorizations carry a time window. `validAfter=0` is normal
        # for this scheme; the important checks are that it is not in the
        # future and `validBefore` has not expired or been extended beyond the
        # server's advertised timeout.
        now = int(time.time())
        valid_after = self._parse_integer(authorization.get("validAfter"))
        valid_before = self._parse_integer(authorization.get("validBefore"))
        after_ok = valid_after is not None and valid_after <= now
        check(
            "valid_after",
            after_ok,
            "Authorization is already valid.",
            "Authorization validAfter is invalid or in the future.",
        )
        before_ok = (
            valid_before is not None
            and valid_before > now
            and valid_before <= now + self.config.max_timeout_seconds + 2
        )
        check(
            "valid_before",
            before_ok,
            "Authorization is not expired and stays within the timeout.",
            "Authorization is expired or exceeds the allowed timeout.",
        )

        nonce = authorization.get("nonce")
        nonce_is_well_formed = (
            isinstance(nonce, str)
            and _NONCE_PATTERN.fullmatch(nonce) is not None
        )
        check(
            "nonce_format",
            nonce_is_well_formed,
            "Authorization has a 32-byte hex nonce.",
            "Authorization nonce must be 32 bytes of hex with a 0x prefix.",
        )

        # CRITICAL MOCK LIMITATION: this compares a literal marker. It does not
        # recover an address from ECDSA or prove wallet ownership. Only the
        # official SDK's payload construction is real in this demo.
        signature = payload.get("signature")
        signature_is_mock = isinstance(signature, str) and hmac.compare_digest(
            signature, self.config.mock_signature
        )
        check(
            "mock_signature_marker",
            signature_is_mock,
            "The exact local mock marker is present (not a real signature).",
            "Missing or different mock marker; real signatures are not accepted here.",
        )

        # A mock request with the correct shape can still be resent. Remember
        # each accepted nonce in this process and reject its later reuse.
        basic_checks_passed = all(item.passed for item in checks)
        if basic_checks_passed:
            with self._nonce_lock:
                if nonce in self._used_nonces:
                    check("nonce_replay", False, "", "This authorization nonce was already used.")
                else:
                    self._used_nonces.add(nonce)
                    check("nonce_replay", True, "Authorization nonce has not been used before.", "")
        else:
            check(
                "nonce_replay",
                True,
                "Replay check skipped because another check already denied this payload.",
                "",
            )

        decision = GuardDecision(
            authorized=all(item.passed for item in checks),
            checks=tuple(checks),
        )
        self._last_decision = decision
        return decision

    @staticmethod
    def _parse_integer(value: Any) -> int | None:
        """Read an integer or decimal string without accepting floats/bools."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdecimal():
            try:
                return int(value)
            except ValueError:
                return None
        return None
