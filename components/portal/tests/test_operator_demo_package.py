import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "demo_operator_package.py"
SPEC = importlib.util.spec_from_file_location("demo_operator_package", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {SCRIPT_PATH}")
demo_operator_package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo_operator_package)


class OperatorDemoPackageTests(unittest.TestCase):
    def test_json_summary_is_synthetic_and_meaningful(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        payload = json.loads(result.stdout)

        self.assertEqual(payload["safety"], "Demo completed without touching live portal/OpenCTI state.")
        self.assertGreaterEqual(payload["summary"]["open_tasks"], 1)
        self.assertGreaterEqual(payload["summary"]["document_count"], 2)
        self.assertGreaterEqual(payload["board_analytics"]["blocked_count"], 1)
        self.assertGreaterEqual(payload["board_analytics"]["review_count"], 1)
        self.assertTrue(any(item["org_alias"] == "Client Atlas" for item in payload["clients"]))
        self.assertIn("/dashboard", payload["guided_ui_path"])
        self.assertIn("/security", payload["guided_ui_path"])
        self.assertTrue(payload["notifications"])
        self.assertTrue(payload["focus_queue"])

    def test_transcript_contains_operator_walkthrough_sections(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout
        for expected in [
            "[1] Seeded synthetic state",
            "[2] Dashboard and board signal",
            "[3] Priority queue",
            "[4] Documents and client context",
            "[5] Guided UI path",
            "[6] Operator notifications",
            "SAFETY: Demo completed without touching live portal/OpenCTI state.",
        ]:
            self.assertIn(expected, output)


if __name__ == "__main__":
    unittest.main()
