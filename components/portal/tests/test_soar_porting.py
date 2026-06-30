import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
sys.path.insert(0, str(APP_PATH.parent))
SPEC = importlib.util.spec_from_file_location("portal_app_soar_porting", APP_PATH)
portal_app = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(portal_app)


class DummyRequest:
    def __init__(self, authenticated: bool = True):
        self.session = {}
        self.client = type("Client", (), {"host": "127.0.0.1"})()
        self.query_params = {}
        if authenticated:
            self.session.update({"user_id": 1, "username": "tester", "display_name": "Tester", "role": "admin", "mfa_ok": True})


class JsonRequest(DummyRequest):
    def __init__(self, payload: dict, authenticated: bool = True):
        super().__init__(authenticated=authenticated)
        self._payload = payload

    async def json(self):
        return self._payload


class SoarPortingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.playbooks_dir = self.root / "playbooks"
        self.playbooks_dir.mkdir(parents=True, exist_ok=True)
        (self.playbooks_dir / "phishing-triage.yaml").write_text(
            """
key: phishing-triage
title: Phishing triage
scope: it
trigger: manual
description: Triage suspected phishing with analyst checkpoints.
steps:
  - id: collect_headers
    action: collect-headers
  - id: enrich_sender
    action: enrich-sender
""".strip() + "\n",
            encoding="utf-8",
        )
        self.originals = {
            "DATA_DIR": portal_app.DATA_DIR,
            "UPLOAD_DIR": portal_app.UPLOAD_DIR,
            "DOCUMENTS_DIR": portal_app.DOCUMENTS_DIR,
            "IN_REVIEW_DIR": portal_app.IN_REVIEW_DIR,
            "DB_PATH": portal_app.DB_PATH,
            "PLAYBOOKS_DIR": getattr(getattr(portal_app, "workflow_registry", object()), "PLAYBOOKS_DIR", None),
        }
        portal_app.DATA_DIR = self.root / "data"
        portal_app.UPLOAD_DIR = portal_app.DATA_DIR / "uploads"
        portal_app.DOCUMENTS_DIR = portal_app.DATA_DIR / "documents"
        portal_app.IN_REVIEW_DIR = portal_app.DOCUMENTS_DIR / "In Review"
        portal_app.DB_PATH = portal_app.DATA_DIR / "portal.db"
        portal_app.DATA_DIR.mkdir(parents=True, exist_ok=True)
        portal_app.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        portal_app.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
        portal_app.IN_REVIEW_DIR.mkdir(parents=True, exist_ok=True)
        portal_app.init_db()
        if hasattr(portal_app, "workflow_registry"):
            portal_app.workflow_registry.PLAYBOOKS_DIR = self.playbooks_dir

    def tearDown(self):
        for name, value in self.originals.items():
            if name == "PLAYBOOKS_DIR":
                if hasattr(portal_app, "workflow_registry") and value is not None:
                    portal_app.workflow_registry.PLAYBOOKS_DIR = value
                continue
            setattr(portal_app, name, value)
        self.tmp.cleanup()

    def test_soar_dashboard_pages_render(self):
        response = portal_app.soar_page(DummyRequest())
        html = response.body.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("SOAR command center", html)
        self.assertIn("href=\"/cases\"", html)
        self.assertIn("href=\"/playbooks\"", html)
        self.assertIn("Create a case from an alert", html)

    def test_api_create_case_and_launch_playbook(self):
        create_response = portal_app.asyncio.run(
            portal_app.api_create_case(
                JsonRequest({
                    "title": "Mailbox triage",
                    "summary": "Investigate suspicious message.",
                    "case_type": "email",
                    "severity": "high",
                    "tags": ["phishing"],
                    "playbook_key": "phishing-triage",
                })
            )
        )
        self.assertEqual(create_response.status_code, 201)
        payload = json.loads(create_response.body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["case"]["title"], "Mailbox triage")
        self.assertEqual(payload["run"]["playbook_key"], "phishing-triage")

    def test_launch_playbook_route_creates_run(self):
        case_id = portal_app.create_case(
            title="Linked case",
            summary="Run a playbook against this case.",
            requested_by="tester",
            case_type="it_triage",
            severity="high",
            source="portal",
            tags=["phishing"],
        )
        response = portal_app.launch_playbook_route(DummyRequest(), playbook_key="phishing-triage", case_id=case_id)
        self.assertEqual(response.status_code, 303)
        runs = portal_app.fetch_workflow_runs(limit=10)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["case_id"], case_id)
        self.assertEqual(runs[0]["playbook_key"], "phishing-triage")


if __name__ == "__main__":
    unittest.main()
