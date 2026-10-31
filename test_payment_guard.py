"""Focused tests for the local authorization checks in payment_guard.py."""

import time
import unittest

import server
from payment_guard import GuardConfig, PaymentGuard


def make_guard():
    """Create an isolated guard so a test's replay cache is independent."""
    return PaymentGuard(
        GuardConfig(
            scheme="exact",
            network=server.NETWORK,
            amount=server.PRICE,
            asset=server.ASSET,
            pay_to=server.PAY_TO,
            mock_signature=server.MOCK_SIGNATURE,
            allowed_payers=frozenset({server.MOCK_PAYER}),
            max_timeout_seconds=60,
        )
    )


def valid_mock_payment(resource_url, nonce="0x" + "11" * 32):
    """Build a shape-correct payment fixture; the signature is still fake."""
    return {
        "x402Version": 2,
        "resource": {"url": resource_url},
        "accepted": {
            "scheme": "exact",
            "network": server.NETWORK,
            "amount": server.PRICE,
            "asset": server.ASSET,
            "payTo": server.PAY_TO,
        },
        "payload": {
            "signature": server.MOCK_SIGNATURE,
            "authorization": {
                "from": server.MOCK_PAYER,
                "to": server.PAY_TO,
                "value": server.PRICE,
                "validAfter": "0",
                "validBefore": str(int(time.time()) + 30),
                "nonce": nonce,
            },
        },
    }


class PaymentGuardTests(unittest.TestCase):
    def test_matching_terms_authorize_once_then_replay_is_denied(self):
        guard = make_guard()
        payment = valid_mock_payment("http://localhost:8402/paid")

        first = guard.authorize(payment, "http://localhost:8402/paid")
        self.assertTrue(first.authorized)
        self.assertIn("nonce_replay", [check.name for check in first.checks])

        second = guard.authorize(payment, "http://localhost:8402/paid")
        self.assertFalse(second.authorized)
        self.assertIn("already used", " ".join(second.reasons))

    def test_wrong_recipient_and_amount_are_denied(self):
        guard = make_guard()
        payment = valid_mock_payment("http://localhost:8402/paid")
        payment["payload"]["authorization"]["to"] = "0x0000000000000000000000000000000000000001"
        payment["payload"]["authorization"]["value"] = "1"

        decision = guard.authorize(payment, "http://localhost:8402/paid")
        self.assertFalse(decision.authorized)
        failed = {check.name for check in decision.checks if not check.passed}
        self.assertIn("authorization_destination", failed)
        self.assertIn("authorization_amount", failed)

    def test_expired_authorization_is_denied(self):
        guard = make_guard()
        payment = valid_mock_payment("http://localhost:8402/paid")
        payment["payload"]["authorization"]["validBefore"] = "1"

        decision = guard.authorize(payment, "http://localhost:8402/paid")
        self.assertFalse(decision.authorized)
        self.assertIn("valid_before", {check.name for check in decision.checks if not check.passed})


if __name__ == "__main__":
    unittest.main()
