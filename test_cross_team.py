"""Tests for shared dry-run scenarios and the decision-only peer interface."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import mock_pay
import server
from attack_suite import OFFICIAL_SCENARIOS, RESOURCE_URL, SCENARIOS, offer_for_scenario
from cross_team_test import evaluate_peer, run_suite
from payer_agent import DeterministicPaymentAgent


class SharedScenarioTests(unittest.TestCase):
    def test_official_scenario_ids_and_expected_outcomes_are_stable(self):
        self.assertEqual(
            [(scenario.scenario_id, scenario.expected_authorized) for scenario in OFFICIAL_SCENARIOS],
            [("baseline_valid", True), ("overpayment", False), ("wrong_party", False)],
        )
        agent = DeterministicPaymentAgent()
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.scenario_id):
                decision = agent.evaluate(offer_for_scenario(scenario.scenario_id), RESOURCE_URL)
                self.assertIs(decision.authorized, scenario.expected_authorized)

    def test_local_runner_reports_expected_actual_checks_and_attack_status(self):
        result = run_suite()
        self.assertTrue(result["summary"]["all_scenarios_passed"])
        self.assertTrue(result["summary"]["baseline_passed"])
        self.assertTrue(result["summary"]["overpayment_blocked"])
        self.assertTrue(result["summary"]["wrong_party_blocked"])
        for scenario_result in result["results"]:
            self.assertIsNotNone(scenario_result["actual"])
            self.assertTrue(scenario_result["checks"])
            self.assertIsNone(scenario_result["error"])
            self.assertFalse(scenario_result["signing_attempted"])
            self.assertFalse(scenario_result["payment_submitted"])

    def test_unavailable_peer_is_reported_as_error_not_a_pass(self):
        result = run_suite("http://127.0.0.1:1/evaluate", timeout=0.2)
        self.assertFalse(result["summary"]["all_scenarios_passed"])
        self.assertFalse(result["summary"]["baseline_passed"])
        for scenario_result in result["results"]:
            self.assertIsNone(scenario_result["actual"])
            self.assertTrue(scenario_result["error"])
            self.assertFalse(scenario_result["passed"])

    def test_peer_runner_reports_malformed_responses(self):
        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"not-json"

        with patch("cross_team_test.urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(RuntimeError, "malformed JSON"):
                evaluate_peer("http://peer.invalid/evaluate", "baseline_valid", offer_for_scenario("baseline_valid"), 1)


class DryRunEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.X402Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}"
        cls.endpoint = f"{cls.base_url}/evaluate"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def post(self, payload):
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            result = (error.code, json.loads(error.read()))
            error.close()
            return result

    def test_peer_endpoint_returns_only_a_decision_and_never_signs_or_submits(self):
        with patch.object(mock_pay.MockEvmSigner, "sign_typed_data") as signer:
            for scenario in SCENARIOS:
                with self.subTest(scenario=scenario.scenario_id):
                    status, result = self.post(
                        {"scenario_id": scenario.scenario_id, "offer": offer_for_scenario(scenario.scenario_id)}
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(result["scenario_id"], scenario.scenario_id)
                    self.assertIs(result["authorized"], scenario.expected_authorized)
                    self.assertIsInstance(result["checks"], list)
                    self.assertIsInstance(result["reasons"], list)
                    self.assertFalse(result["signing_attempted"])
                    self.assertFalse(result["payment_submitted"])
            signer.assert_not_called()

    def test_gui_and_scenario_manifest_are_served(self):
        with urlopen(self.base_url + "/cross-team", timeout=2) as response:
            html = response.read().decode("utf-8")
        self.assertIn("x402 Guard Attack Suite", html)
        self.assertIn("What happened", html)
        self.assertIn("Run full suite", html)

        with urlopen(self.base_url + "/cross-team/scenarios", timeout=2) as response:
            manifest = json.load(response)
        self.assertEqual(
            [item["scenario_id"] for item in manifest["scenarios"]],
            [scenario.scenario_id for scenario in SCENARIOS],
        )
        self.assertTrue(
            all(isinstance(item["offer"], (dict, list)) for item in manifest["scenarios"])
        )

    def test_endpoint_rejects_untrusted_policy_fields(self):
        status, result = self.post(
            {
                "scenario_id": "baseline_valid",
                "offer": offer_for_scenario("baseline_valid"),
                "policy": {"max_amount_atomic": 999999999},
            }
        )
        self.assertEqual(status, 400)
        self.assertIn("only_scenario_id_and_offer", result["error"])

    def test_malformed_offer_is_decided_as_deny_without_payment(self):
        status, result = self.post({"scenario_id": "malformed", "offer": {"accepts": "not-an-array"}})
        self.assertEqual(status, 200)
        self.assertFalse(result["authorized"])
        self.assertTrue(result["reasons"])
        self.assertFalse(result["signing_attempted"])
        self.assertFalse(result["payment_submitted"])

    def test_runner_can_target_peer_endpoint(self):
        result = run_suite(self.endpoint, timeout=2)
        self.assertEqual(result["mode"], "peer_http_dry_run")
        self.assertTrue(result["summary"]["all_scenarios_passed"])
        self.assertEqual(result["summary"]["attacks_succeeded"], [])


if __name__ == "__main__":
    unittest.main()
