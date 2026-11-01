"""Deterministic payer-side policy for x402 offers.

The resource's 402 response is untrusted input. This module keeps the agent's
spending policy in a separate, trusted object and checks the offer against
that policy before asking the x402 SDK to create a payment payload. A rejected
offer never reaches the signer.

This file uses the SDK's mock signer interface in the local prototype; a real
wallet should be placed behind the same `authorize_then_build_payload` gate.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any


POLICY_AMOUNT_CEILING = 10_000
POLICY_NETWORK = "eip155:84532"
POLICY_ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class AgentPolicy:
    """Trusted limits owned by the payer, independent of any 402 response.

    These defaults are the agent's intent for the hackathon prototype: pay at
    most 0.01 USDC per request and per rolling hour, at most 0.03 USDC per
    rolling day, and only to the listed recipient on Base Sepolia. Adjust this
    policy deliberately; never copy limits from a server challenge into it.
    """

    max_amount_atomic: int = 10_000
    rolling_hour_budget_atomic: int = 10_000
    rolling_day_budget_atomic: int = 30_000
    approved_recipients: frozenset[str] = frozenset(
        {"0x209693Bc6afc0C5328bA36FaF03C514EF312287C"}
    )
    approved_assets: frozenset[str] = frozenset({POLICY_ASSET})
    approved_networks: frozenset[str] = frozenset({POLICY_NETWORK})
    approved_schemes: frozenset[str] = frozenset({"exact"})

    def to_dict(self) -> dict[str, Any]:
        """Make the payer policy visible in the local demo output."""

        def safe_values(values: Any) -> list[str]:
            if isinstance(values, (set, frozenset, tuple, list)) and all(
                isinstance(value, str) for value in values
            ):
                return sorted(values)
            return []

        return {
            "max_amount_atomic": (
                self.max_amount_atomic
                if type(self.max_amount_atomic) is int
                else None
            ),
            "rolling_hour_budget_atomic": self.rolling_hour_budget_atomic,
            "rolling_day_budget_atomic": self.rolling_day_budget_atomic,
            "approved_recipients": safe_values(self.approved_recipients),
            "approved_assets": safe_values(self.approved_assets),
            "approved_networks": safe_values(self.approved_networks),
            "approved_schemes": safe_values(self.approved_schemes),
            "source": "agent configuration; not read from the 402 offer",
        }

    def validation_errors(self) -> list[str]:
        """Reject missing, malformed, or unsupported trusted policy settings."""
        errors: list[str] = []
        if (
            type(self.max_amount_atomic) is not int
            or not 1 <= self.max_amount_atomic <= POLICY_AMOUNT_CEILING
        ):
            errors.append(f"Maximum amount must be an integer from 1 to {POLICY_AMOUNT_CEILING}.")
        for name, value in (
            ("Rolling hour budget", self.rolling_hour_budget_atomic),
            ("Rolling day budget", self.rolling_day_budget_atomic),
        ):
            if type(value) is not int or value < 1:
                errors.append(f"{name} must be a positive integer number of atomic units.")

        recipients = self.approved_recipients
        if (
            not isinstance(recipients, frozenset)
            or not recipients
            or any(
                not isinstance(value, str) or _ADDRESS.fullmatch(value) is None
                for value in recipients
            )
        ):
            errors.append("Approved recipients must be a non-empty set of valid EVM addresses.")

        assets = self.approved_assets
        if (
            not isinstance(assets, frozenset)
            or not assets
            or any(
                not isinstance(value, str) or value.lower() != POLICY_ASSET.lower()
                for value in assets
            )
        ):
            errors.append("Approved asset policy must contain only Base Sepolia USDC.")

        networks = self.approved_networks
        if not isinstance(networks, frozenset) or networks != frozenset({POLICY_NETWORK}):
            errors.append(f"Approved network policy must be exactly {POLICY_NETWORK}.")

        schemes = self.approved_schemes
        if not isinstance(schemes, frozenset) or schemes != frozenset({"exact"}):
            errors.append("Approved scheme policy must be exactly 'exact'.")
        return errors


@dataclass(frozen=True)
class PolicyCheck:
    """One deterministic policy result for the GUI and audit log."""

    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class PayerDecision:
    """The pre-signing decision made by the payer-side agent."""

    authorized: bool
    checks: tuple[PolicyCheck, ...]
    policy: dict[str, Any]

    @property
    def reasons(self) -> list[str]:
        return [check.detail for check in self.checks if not check.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_owner": "payer_agent",
            "authorized": self.authorized,
            "checks": [asdict(check) for check in self.checks],
            "reasons": self.reasons,
            "trusted_policy": self.policy,
        }


class InMemorySpendLedger:
    """Thread-safe prototype ledger for settled spend and pending reservations.

    This deliberately uses process memory. A production payer must replace it
    with durable transactional storage shared by every signer process.
    """

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[int, float, str]] = {}

    def reserve(
        self,
        amount: int,
        hourly_limit: int,
        daily_limit: int,
        reservation_id: str | None = None,
    ) -> tuple[str | None, str]:
        """Atomically reserve spend if both sliding-window limits allow it."""
        now = self._clock()
        key = reservation_id or str(uuid.uuid4())
        with self._lock:
            # Entries older than the longest configured rolling window can no
            # longer affect a budget, so discard them to bound prototype memory.
            self._entries = {
                entry_id: entry
                for entry_id, entry in self._entries.items()
                if entry[1] > now - 86400
            }
            existing = self._entries.get(key)
            if existing:
                return None, "Reservation ID has already been used; duplicate authorization denied."
            hour_spend = sum(
                value for value, created, _ in self._entries.values()
                if created > now - 3600
            )
            day_spend = sum(
                value for value, created, _ in self._entries.values()
                if created > now - 86400
            )
            if hour_spend + amount > hourly_limit:
                return None, (
                    f"Rolling 1-hour budget exceeded: {hour_spend} already spent or reserved; "
                    f"limit is {hourly_limit} atomic units."
                )
            if day_spend + amount > daily_limit:
                return None, (
                    f"Rolling 24-hour budget exceeded: {day_spend} already spent or reserved; "
                    f"limit is {daily_limit} atomic units."
                )
            self._entries[key] = (amount, now, "reserved")
            return key, "Payment amount reserved within rolling 1-hour and 24-hour budgets."

    def settle(self, reservation_id: str) -> bool:
        """Mark a reservation settled; settled spend continues counting in windows."""
        with self._lock:
            entry = self._entries.get(reservation_id)
            if entry is None:
                return False
            self._entries[reservation_id] = (entry[0], entry[1], "settled")
            return True

    def release(self, reservation_id: str) -> bool:
        """Remove a reservation after a definite pre-settlement failure."""
        with self._lock:
            return self._entries.pop(reservation_id, None) is not None


class DeterministicPaymentAgent:
    """Evaluate 402 requirements using fixed policy, then optionally sign.

    Decision-making is deterministic: the same offer and policy always produce
    the same ALLOW/DENY checks. There is no model call, random choice, or
    network-provided policy. SDK payload construction only happens after ALLOW.
    """

    def __init__(
        self,
        policy: AgentPolicy | None = None,
        signer: Any | None = None,
        ledger: InMemorySpendLedger | None = None,
    ) -> None:
        self.policy = AgentPolicy() if policy is None else policy
        self.signer = signer
        self.ledger = InMemorySpendLedger() if ledger is None else ledger
        self.last_reservation_id: str | None = None

    def evaluate(self, requirements: Any, requested_resource_url: str) -> PayerDecision:
        """Compare a parsed, untrusted 402 object with the agent's own policy."""
        checks: list[PolicyCheck] = []

        def add(name: str, passed: bool, success: str, failure: str) -> None:
            checks.append(PolicyCheck(name, passed, success if passed else failure))

        policy_errors = (
            self.policy.validation_errors() if isinstance(self.policy, AgentPolicy)
            else ["Trusted payer policy is missing or has an unsupported type."]
        )
        add(
            "trusted_policy",
            not policy_errors,
            "Trusted payer policy is complete and supported.",
            "Invalid trusted payer policy: " + " ".join(policy_errors),
        )

        # A malformed policy must fail closed. Normalize its fields into safe
        # values so later comparisons cannot accidentally grant permission or
        # throw while handling an untrusted offer.
        raw_policy = self.policy if isinstance(self.policy, AgentPolicy) else None

        def safe_string_set(values: Any) -> frozenset[str]:
            if isinstance(values, frozenset):
                return frozenset(value for value in values if isinstance(value, str))
            return frozenset()

        policy = AgentPolicy(
            max_amount_atomic=(
                raw_policy.max_amount_atomic
                if raw_policy and type(raw_policy.max_amount_atomic) is int
                else 0
            ),
            rolling_hour_budget_atomic=(
                raw_policy.rolling_hour_budget_atomic
                if raw_policy and type(raw_policy.rolling_hour_budget_atomic) is int
                else 0
            ),
            rolling_day_budget_atomic=(
                raw_policy.rolling_day_budget_atomic
                if raw_policy and type(raw_policy.rolling_day_budget_atomic) is int
                else 0
            ),
            approved_recipients=(
                safe_string_set(raw_policy.approved_recipients)
                if raw_policy
                else frozenset()
            ),
            approved_assets=(
                safe_string_set(raw_policy.approved_assets)
                if raw_policy
                else frozenset()
            ),
            approved_networks=(
                safe_string_set(raw_policy.approved_networks)
                if raw_policy
                else frozenset()
            ),
            approved_schemes=(
                safe_string_set(raw_policy.approved_schemes)
                if raw_policy
                else frozenset()
            ),
        )

        # Validate the outer structure first. The parser checks wire syntax;
        # this step decides whether the content is safe for this payer.
        is_object = isinstance(requirements, dict)
        add(
            "requirements_object",
            is_object,
            "Parsed requirements are an object.",
            "Requirements must be an object.",
        )
        requirements = requirements if is_object else {}

        add(
            "x402_version",
            requirements.get("x402Version") == 2,
            "Offer uses x402 v2.",
            "Offer must use x402 version 2.",
        )

        resource = requirements.get("resource")
        resource = resource if isinstance(resource, dict) else {}
        add(
            "resource_url",
            resource.get("url") == requested_resource_url,
            "Offer is for the resource the agent requested.",
            "Offer resource URL does not match the agent's request.",
        )

        accepts = requirements.get("accepts")
        accepts = accepts if isinstance(accepts, list) else []
        exactly_one_option = len(accepts) == 1 and isinstance(accepts[0], dict)
        add(
            "offer_count",
            exactly_one_option,
            "Offer has one unambiguous payment option.",
            "Agent requires exactly one payment option for this prototype.",
        )
        offer = accepts[0] if exactly_one_option else {}

        scheme = offer.get("scheme")
        scheme_ok = isinstance(scheme, str) and scheme in policy.approved_schemes
        add(
            "approved_scheme",
            scheme_ok,
            f"Scheme {scheme!r} is approved by agent policy.",
            f"Scheme {scheme!r} is not approved by agent policy.",
        )

        network = offer.get("network")
        network_ok = isinstance(network, str) and network in policy.approved_networks
        add(
            "approved_network",
            network_ok,
            f"Network {network!r} is approved by agent policy.",
            f"Network {network!r} is not approved by agent policy.",
        )

        # x402 prices are integer atomic units represented as decimal strings.
        # Parse strictly, and compare to the agent's own ceiling. The offer
        # cannot raise this ceiling by claiming a different price.
        amount_text = offer.get("amount")
        amount = self._parse_atomic_amount(amount_text)
        amount_ok = amount is not None and amount <= policy.max_amount_atomic
        add(
            "max_amount",
            amount_ok,
            f"Offer amount {amount} is within the agent limit {policy.max_amount_atomic}.",
            "Offer amount "
            f"{amount_text!r} is invalid or exceeds the agent limit "
            f"{policy.max_amount_atomic}.",
        )

        asset = offer.get("asset")
        asset_ok = isinstance(asset, str) and self._contains_case_insensitive(
            policy.approved_assets, asset
        )
        add(
            "approved_asset",
            asset_ok,
            f"Token asset {asset!r} is approved by agent policy.",
            f"Token asset {asset!r} is not approved by agent policy.",
        )

        recipient = offer.get("payTo")
        recipient_ok = isinstance(recipient, str) and self._contains_case_insensitive(
            policy.approved_recipients, recipient
        )
        add(
            "approved_recipient",
            recipient_ok,
            f"Recipient {recipient!r} is approved by agent policy.",
            f"Recipient {recipient!r} is not approved by agent policy.",
        )

        return PayerDecision(
            authorized=all(check.passed for check in checks),
            checks=tuple(checks),
            policy=raw_policy.to_dict() if raw_policy else {},
        )

    def authorize_and_reserve(
        self,
        requirements: Any,
        requested_resource_url: str,
        reservation_id: str | None = None,
    ) -> tuple[PayerDecision, str | None]:
        """Evaluate an offer and atomically reserve its amount against budgets."""
        decision = self.evaluate(requirements, requested_resource_url)
        if not decision.authorized:
            return decision, None
        try:
            amount = self._parse_atomic_amount(requirements["accepts"][0]["amount"])
        except (KeyError, IndexError, TypeError):
            amount = None
        if amount is None:
            check = PolicyCheck(
                "rolling_budget",
                False,
                "Could not reserve malformed payment amount.",
            )
            return PayerDecision(False, decision.checks + (check,), decision.policy), None
        policy = self.policy
        key, detail = self.ledger.reserve(
            amount,
            policy.rolling_hour_budget_atomic,
            policy.rolling_day_budget_atomic,
            reservation_id,
        )
        budget_check = PolicyCheck("rolling_budget", key is not None, detail)
        return (
            PayerDecision(key is not None, decision.checks + (budget_check,), decision.policy),
            key,
        )

    def deny_malformed_offer(self, reason: str) -> PayerDecision:
        """Create an explicit fail-closed decision when parsing/schema fails."""
        policy_errors = (
            self.policy.validation_errors() if isinstance(self.policy, AgentPolicy)
            else ["Trusted payer policy is missing or has an unsupported type."]
        )
        checks = [PolicyCheck("offer_schema", False, f"Offer rejected before signing: {reason}")]
        if policy_errors:
            checks.append(PolicyCheck("trusted_policy", False, " ".join(policy_errors)))
        policy_view = self.policy.to_dict() if isinstance(self.policy, AgentPolicy) else {}
        return PayerDecision(authorized=False, checks=tuple(checks), policy=policy_view)

    def authorize_then_build_payload(
        self,
        requirements: dict[str, Any],
        requested_resource_url: str,
    ) -> tuple[PayerDecision, Any | None]:
        """Block first; only ask the official SDK to sign after an ALLOW.

        The caller should parse the HTTP 402 challenge before calling this
        method. If policy denies, this returns no payload and never invokes the
        signer's `sign_typed_data`. If policy allows, the official x402 EVM
        exact-scheme SDK creates the EIP-3009 authorization.
        """
        # Validate the complete wire schema before policy evaluation. Decoding
        # an SDK model does not sign; it only ensures malformed/missing fields
        # cannot slip through to the payment builder.
        import base64
        import json

        from x402.http import decode_payment_required_header

        try:
            header = base64.b64encode(
                json.dumps(requirements, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            payment_required = decode_payment_required_header(header)
        except Exception as error:
            return self.deny_malformed_offer(f"x402 SDK schema validation failed: {error}"), None

        decision, reservation_id = self.authorize_and_reserve(requirements, requested_resource_url)
        if not decision.authorized:
            return decision, None

        if self.signer is None:
            if reservation_id:
                self.ledger.release(reservation_id)
            blocked = PayerDecision(
                authorized=False,
                checks=decision.checks
                + (PolicyCheck("signer_available", False, "No signer is configured."),),
                policy=decision.policy,
            )
            return blocked, None

        # Re-encode the exact offer we evaluated, then let the x402 SDK parse it
        # into its typed PaymentRequired model. This keeps the authorization
        # terms identical to the data the policy approved.
        from x402 import x402ClientSync
        from x402.mechanisms.evm.exact import ExactEvmScheme

        self.last_reservation_id = None
        sdk_client = x402ClientSync()
        # This is a mock-only demo: deterministic payer policy above is our
        # explicit authorization boundary; never disable wallet controls this
        # way for a real signer.
        sdk_client.set_spend_controls(False)
        sdk_client.register("eip155:*", ExactEvmScheme(signer=self.signer))
        try:
            payment_payload = sdk_client.create_payment_payload(payment_required)
        except Exception:
            if reservation_id:
                self.ledger.release(reservation_id)
            raise
        # The caller settles or releases this reservation after submission.
        self.last_reservation_id = reservation_id
        return decision, payment_payload

    @staticmethod
    def _parse_atomic_amount(value: Any) -> int | None:
        if not isinstance(value, str) or not value.isdecimal():
            return None
        try:
            amount = int(value)
            return amount if amount > 0 else None
        except ValueError:
            return None

    @staticmethod
    def _contains_case_insensitive(values: frozenset[str], candidate: str) -> bool:
        candidate_lower = candidate.lower()
        return any(value.lower() == candidate_lower for value in values)
