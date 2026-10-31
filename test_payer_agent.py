"""Tests that the deterministic payer agent decides before signer access."""

import unittest

from payer_agent import AgentPolicy, DeterministicPaymentAgent


RESOURCE_URL = "http://127.0.0.1:8402/paid"


class CountingSigner:
    address = "0x857b06519E91e3A54538791bDbb0E22373e36b66"

    def __init__(self):
        self.calls = 0

    def sign_typed_data(self, domain, types, primary_type, message):
        self.calls += 1
        return b"MOCK-TEST-ONLY"


def offer(amount="10000", recipient="0x209693Bc6afc0C5328bA36FaF03C514EF312287C"):
    return {
        "x402Version": 2,
        "resource": {"url": RESOURCE_URL},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:84532",
                "amount": amount,
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": recipient,
                "maxTimeoutSeconds": 60,
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
    }


class DeterministicPaymentAgentTests(unittest.TestCase):
    def test_same_offer_and_policy_give_same_decision(self):
        agent = DeterministicPaymentAgent(AgentPolicy())
        left = agent.evaluate(offer(), RESOURCE_URL)
        right = agent.evaluate(offer(), RESOURCE_URL)
        self.assertEqual(left, right)
        self.assertTrue(left.authorized)

    def test_exact_cap_is_allowed_and_calls_the_mock_signer(self):
        signer = CountingSigner()
        agent = DeterministicPaymentAgent(AgentPolicy(), signer)
        decision, payload = agent.authorize_then_build_payload(offer(amount="10000"), RESOURCE_URL)
        self.assertTrue(decision.authorized)
        self.assertIsNotNone(payload)
        self.assertEqual(signer.calls, 1)

    def test_overpayment_is_denied_before_signer_is_called(self):
        signer = CountingSigner()
        agent = DeterministicPaymentAgent(AgentPolicy(), signer)
        decision, payload = agent.authorize_then_build_payload(offer(amount="10001"), RESOURCE_URL)
        self.assertFalse(decision.authorized)
        self.assertIsNone(payload)
        self.assertEqual(signer.calls, 0)
        self.assertIn("max_amount", {check.name for check in decision.checks if not check.passed})

    def test_wrong_party_is_denied_before_signer_is_called(self):
        signer = CountingSigner()
        changed = offer(recipient="0x0000000000000000000000000000000000000001")
        decision, payload = DeterministicPaymentAgent(AgentPolicy(), signer).authorize_then_build_payload(
            changed, RESOURCE_URL
        )
        self.assertFalse(decision.authorized)
        self.assertIsNone(payload)
        self.assertEqual(signer.calls, 0)

    def test_unapproved_network_and_asset_are_denied_before_signing(self):
        variants = [
            ("network", "eip155:8453"),
            ("asset", "0x0000000000000000000000000000000000000002"),
        ]
        for field, value in variants:
            with self.subTest(field=field):
                signer = CountingSigner()
                changed = offer()
                changed["accepts"][0][field] = value
                decision, payload = DeterministicPaymentAgent(AgentPolicy(), signer).authorize_then_build_payload(
                    changed, RESOURCE_URL
                )
                self.assertFalse(decision.authorized)
                self.assertIsNone(payload)
                self.assertEqual(signer.calls, 0)

    def test_invalid_amounts_are_denied_before_signing(self):
        for amount in ("invalid", "-1", "1.5", "0", None, 10_000, True):
            with self.subTest(amount=amount):
                signer = CountingSigner()
                decision, payload = DeterministicPaymentAgent(AgentPolicy(), signer).authorize_then_build_payload(
                    offer(amount=amount), RESOURCE_URL
                )
                self.assertFalse(decision.authorized)
                self.assertIsNone(payload)
                self.assertEqual(signer.calls, 0)

    def test_missing_malformed_or_ambiguous_options_are_denied_before_signing(self):
        malformed_offers = []

        missing = offer()
        del missing["accepts"]
        malformed_offers.append(("missing accepts", missing))

        null_options = offer()
        null_options["accepts"] = None
        malformed_offers.append(("null accepts", null_options))

        no_options = offer()
        no_options["accepts"] = []
        malformed_offers.append(("empty accepts", no_options))

        multiple = offer()
        multiple["accepts"].append(dict(multiple["accepts"][0]))
        malformed_offers.append(("multiple accepts", multiple))

        malformed_option = offer()
        malformed_option["accepts"] = [None]
        malformed_offers.append(("malformed option", malformed_option))

        missing_recipient = offer()
        del missing_recipient["accepts"][0]["payTo"]
        malformed_offers.append(("missing payTo", missing_recipient))

        for label, requirements in malformed_offers:
            with self.subTest(case=label):
                signer = CountingSigner()
                decision, payload = DeterministicPaymentAgent(AgentPolicy(), signer).authorize_then_build_payload(
                    requirements, RESOURCE_URL
                )
                self.assertFalse(decision.authorized)
                self.assertIsNone(payload)
                self.assertEqual(signer.calls, 0)

    def test_missing_or_malformed_trusted_policy_is_denied(self):
        bad_policies = (
            AgentPolicy(approved_recipients=frozenset()),
            AgentPolicy(max_amount_atomic=None),
            AgentPolicy(approved_networks=frozenset({"eip155:8453"})),
            AgentPolicy(approved_assets=None),
        )
        for policy in bad_policies:
            with self.subTest(policy=policy):
                signer = CountingSigner()
                decision, payload = DeterministicPaymentAgent(policy, signer).authorize_then_build_payload(
                    offer(), RESOURCE_URL
                )
                self.assertFalse(decision.authorized)
                self.assertIsNone(payload)
                self.assertEqual(signer.calls, 0)


if __name__ == "__main__":
    unittest.main()
