import base64
import json
import time
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer

import server
import client
import mock_pay


class X402ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.X402Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def request(self, path="/paid", headers=None):
        request = Request(self.base_url + path, headers=headers or {})
        try:
            response = urlopen(request, timeout=2)
        except HTTPError as error:
            result = (error.code, error.headers, error.read())
            error.close()
            return result
        return response.status, response.headers, response.read()

    @staticmethod
    def decode(value):
        return json.loads(base64.b64decode(value))

    def demo_payment(self):
        resource_url = self.base_url + "/paid"
        payload = {
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
                    "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                    "to": server.PAY_TO,
                    "value": server.PRICE,
                    "validAfter": "0",
                    "validBefore": str(int(time.time()) + 30),
                    "nonce": "0x" + "22" * 32,
                },
            },
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()

    def test_unpaid_request_returns_v2_challenge(self):
        status, headers, body = self.request()
        self.assertEqual(status, 402)
        self.assertEqual(json.loads(body), {})
        challenge = self.decode(headers["PAYMENT-REQUIRED"])
        self.assertEqual(challenge["x402Version"], 2)
        self.assertEqual(challenge["resource"]["url"], self.base_url + "/paid")
        self.assertEqual(challenge["accepts"][0]["scheme"], "exact")
        self.assertEqual(challenge["accepts"][0]["network"], server.NETWORK)
        parsed = client.parse_payment_requirements(headers["PAYMENT-REQUIRED"])
        self.assertEqual(parsed["accepts"][0]["amount"], server.PRICE)

    def test_client_rejects_malformed_challenge_header(self):
        with self.assertRaises(ValueError):
            client.parse_payment_requirements("not-base64-json")

    def test_matching_demo_payment_returns_resource_and_receipt(self):
        status, headers, body = self.request(headers={"PAYMENT-SIGNATURE": self.demo_payment()})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["paymentMode"], "mock")
        receipt = self.decode(headers["PAYMENT-RESPONSE"])
        self.assertTrue(receipt["success"])
        self.assertEqual(receipt["transaction"], "mock-not-settled")

    def test_official_sdk_mock_signer_completes_http_round_trip(self):
        status, headers, body, signer = mock_pay.perform_mock_payment(self.base_url + "/paid")
        self.assertEqual(status, 200)
        self.assertEqual(body["paymentMode"], "mock")
        self.assertEqual(signer.last_signing_request["primary_type"], "TransferWithAuthorization")
        self.assertEqual(signer.last_signing_request["message"]["value"], int(server.PRICE))
        self.assertIn("PAYMENT-RESPONSE", headers)

    def test_wrong_payment_amount_is_challenged(self):
        payment = json.loads(base64.b64decode(self.demo_payment()))
        payment["accepted"]["amount"] = "1"
        header = base64.b64encode(json.dumps(payment).encode()).decode()
        status, headers, _ = self.request(headers={"PAYMENT-SIGNATURE": header})
        self.assertEqual(status, 402)
        challenge = self.decode(headers["PAYMENT-REQUIRED"])
        self.assertIn("amount", challenge["error"])

    def test_year_long_authorization_is_rejected_over_http(self):
        payment = json.loads(base64.b64decode(self.demo_payment()))
        payment["payload"]["authorization"]["validBefore"] = str(
            int(time.time()) + 365 * 24 * 60 * 60
        )
        header = base64.b64encode(json.dumps(payment).encode()).decode()

        status, headers, _ = self.request(headers={"PAYMENT-SIGNATURE": header})
        self.assertEqual(status, 402)
        challenge = self.decode(headers["PAYMENT-REQUIRED"])
        self.assertIn("timeout", challenge["error"])

    def test_malformed_resource_is_challenged_without_server_error(self):
        payment = json.loads(base64.b64decode(self.demo_payment()))
        payment["resource"] = None
        header = base64.b64encode(json.dumps(payment).encode()).decode()
        status, headers, _ = self.request(headers={"PAYMENT-SIGNATURE": header})
        self.assertEqual(status, 402)
        self.assertEqual(self.decode(headers["PAYMENT-REQUIRED"])["x402Version"], 2)

    def test_health_and_unknown_route(self):
        self.assertEqual(self.request("/health")[0], 200)
        self.assertEqual(self.request("/missing")[0], 404)

    def test_localhost_explainer_runs_full_flow_and_shows_guard_checks(self):
        status, _, html = self.request("/demo")
        self.assertEqual(status, 200)
        self.assertIn(b"Local x402 payment guard", html)
        stage_labels = [
            b"1 \xc2\xb7 Parse offer",
            b"2 \xc2\xb7 Payer policy",
            b"3 \xc2\xb7 Sign only after ALLOW",
            b"4 \xc2\xb7 Retry",
            b"5 \xc2\xb7 Optional server validation",
        ]
        stage_positions = [html.index(label) for label in stage_labels]
        self.assertEqual(stage_positions, sorted(stage_positions))
        self.assertIn(b"Red-team injection point", html)

        status, _, body = self.request("/demo/run")
        self.assertEqual(status, 200)
        demo_result = json.loads(body)
        self.assertEqual(demo_result["flow"][0]["result"], "HTTP 402 Payment Required")
        event_positions = {
            event["event"]: index for index, event in enumerate(demo_result["flow"])
        }
        self.assertLess(
            event_positions["DeterministicPaymentAgent policy"],
            event_positions["SDK signer invocation"],
        )
        self.assertLess(
            event_positions["SDK signer invocation"],
            event_positions["Payment retry"],
        )
        self.assertLess(
            event_positions["Payment retry"],
            event_positions["Resource server guard"],
        )
        self.assertTrue(demo_result["payer_guard_decision"]["authorized"])
        self.assertTrue(demo_result["signing_attempted"])
        self.assertTrue(demo_result["retry_sent"])
        self.assertTrue(demo_result["server_guard_evaluated"])
        self.assertEqual(demo_result["resource_response"]["paymentMode"], "mock")

        status, _, body = self.request("/demo/run?attack=amount&value=20000")
        self.assertEqual(status, 200)  # The lab run completed, although the payer guard stopped payment.
        attacked_result = json.loads(body)
        self.assertFalse(attacked_result["payer_guard_decision"]["authorized"])
        self.assertFalse(attacked_result["red_team_result"]["succeeded"])
        self.assertIn("amount", " ".join(attacked_result["red_team_result"]["why"]))
        self.assertFalse(attacked_result["signing_attempted"])
        self.assertEqual(attacked_result["signer_call_count"], 0)
        self.assertFalse(attacked_result["retry_sent"])
        self.assertFalse(attacked_result["server_guard_evaluated"])
        self.assertEqual(attacked_result["resource_response"]["paymentMode"], "blocked")
        self.assertIn("max_amount", {item["name"] for item in attacked_result["payer_guard_decision"]["checks"]})

    def test_harmless_amount_change_is_not_reported_as_a_successful_attack(self):
        status, _, body = self.request("/demo/run?attack=amount&value=8000")
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result["payer_guard_decision"]["authorized"])
        self.assertTrue(result["signing_attempted"])
        self.assertTrue(result["retry_sent"])
        self.assertFalse(result["red_team_result"]["policy_violated"])
        self.assertFalse(result["red_team_result"]["succeeded"])
        self.assertIn("not successful", result["red_team_result"]["summary"])

    def test_malformed_or_ambiguous_offer_denials_never_sign_or_retry(self):
        base_offer = server.payment_requirements(self.base_url + "/paid")
        scenarios = []

        invalid_amount = json.loads(json.dumps(base_offer))
        invalid_amount["accepts"][0]["amount"] = "not-a-number"
        scenarios.append(("invalid amount", invalid_amount))

        missing_options = json.loads(json.dumps(base_offer))
        del missing_options["accepts"]
        scenarios.append(("missing options", missing_options))

        empty_options = json.loads(json.dumps(base_offer))
        empty_options["accepts"] = []
        scenarios.append(("empty options", empty_options))

        multiple_options = json.loads(json.dumps(base_offer))
        multiple_options["accepts"].append(dict(multiple_options["accepts"][0]))
        scenarios.append(("multiple options", multiple_options))

        malformed_option = json.loads(json.dumps(base_offer))
        malformed_option["accepts"] = [None]
        scenarios.append(("malformed option", malformed_option))

        for label, requirements in scenarios:
            with self.subTest(case=label):
                status, _, _, signer = mock_pay.perform_mock_payment(
                    self.base_url + "/paid",
                    requirements_override_for_test=requirements,
                )
                self.assertEqual(status, 402)
                self.assertFalse(signer.payer_decision["authorized"])
                self.assertEqual(signer.sign_calls, 0)
                self.assertFalse(signer.retry_sent)
                self.assertFalse(signer.server_guard_evaluated)

    def test_red_team_changes_to_each_payment_term_are_denied(self):
        scenarios = [
            ("amount", "20000", "max_amount"),
            ("recipient", "0x0000000000000000000000000000000000000001", "approved_recipient"),
            ("asset", "0x0000000000000000000000000000000000000002", "approved_asset"),
            ("network", "eip155:8453", "approved_network"),
        ]
        for field, value, expected_failed_check in scenarios:
            with self.subTest(field=field):
                status, _, _, signer = mock_pay.perform_mock_payment(
                    self.base_url + "/paid",
                    attack_field=field,
                    attack_value=value,
                )
                self.assertEqual(status, 402)
                self.assertEqual(signer.attack, {"field": field, "value": value})
                self.assertFalse(signer.payer_decision["authorized"])
                self.assertFalse(signer.signing_attempted)
                self.assertEqual(signer.sign_calls, 0)
                self.assertFalse(signer.retry_sent)
                self.assertIn(
                    expected_failed_check,
                    {item["name"] for item in signer.payer_decision["checks"] if not item["passed"]},
                )


if __name__ == "__main__":
    unittest.main()
