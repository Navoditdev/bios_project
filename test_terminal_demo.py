"""Terminal demo output, saved evidence, and failure exit status."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from attack_suite import SCENARIOS
from cross_team_test import main


class TerminalDemoTests(unittest.TestCase):
    def test_live_local_demo_and_saved_report_match_real_guard_results(self):
        output = StringIO()
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            with redirect_stdout(output), redirect_stderr(StringIO()):
                code = main(["--local", "--demo", "--verbose", "--report", str(report_path)])
            report = json.loads(report_path.read_text())
        self.assertEqual(code, 0)
        self.assertTrue(report["summary"]["all_scenarios_passed"])
        self.assertEqual(output.getvalue().count("[PASS]"), len(SCENARIOS))
        self.assertIn("Result: 8/8 cases passed", output.getvalue())
        self.assertIn("Calls: ALLOW -> DENY -> DENY", output.getvalue())
        self.assertIn("OK approved_recipient:", output.getvalue())
        self.assertIn("BLOCK call_5.anomaly_risk:", output.getvalue())
        self.assertTrue(all(not r["signing_attempted"] and not r["payment_submitted"] for r in report["results"]))

    def test_evaluation_errors_are_reported_and_exit_nonzero(self):
        output = StringIO()
        with patch("cross_team_test.evaluate_local", side_effect=RuntimeError("evaluation failed")):
            with redirect_stdout(output):
                code = main(["--local", "--demo"])
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue().count("[ERROR]"), len(SCENARIOS))
        self.assertIn("Result: 0/8 cases passed", output.getvalue())
        self.assertNotIn("[PASS]", output.getvalue())

    def test_unexpected_allow_is_a_failed_test_not_an_error(self):
        decision = {"authorized": True, "checks": [], "reasons": [],
                    "signing_attempted": False, "payment_submitted": False,
                    "call_results": [True, True, True]}
        output = StringIO()
        with patch("cross_team_test.evaluate_local", return_value=decision):
            with redirect_stdout(output):
                code = main(["--local", "--demo"])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] Overpayment", output.getvalue())
        self.assertIn("Expected: DENY | Actual: ALLOW", output.getvalue())
        self.assertNotIn("[ERROR]", output.getvalue())

    def test_report_write_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as errors:
                code = main(["--local", "--demo", "--report", directory])
        self.assertEqual(code, 1)
        self.assertIn("Could not save report:", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
