import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
SPEC = importlib.util.spec_from_file_location("portal_app_intel_ops", APP_PATH)
portal_app = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(portal_app)


class DummyRequest:
    def __init__(self, authenticated: bool = True):
        self.session = {}
        self.client = type("Client", (), {"host": "127.0.0.1"})()
        if authenticated:
            self.session.update({"user_id": 1, "username": "tester", "display_name": "tester", "role": "admin", "mfa_ok": True})


class IntelOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.originals = {
            "DATA_DIR": portal_app.DATA_DIR,
            "UPLOAD_DIR": portal_app.UPLOAD_DIR,
            "DOCUMENTS_DIR": portal_app.DOCUMENTS_DIR,
            "IN_REVIEW_DIR": portal_app.IN_REVIEW_DIR,
            "DB_PATH": portal_app.DB_PATH,
            "PORTAL_KANBAN_DB": portal_app.PORTAL_KANBAN_DB,
            "sync_portal_tasks_with_kanban": portal_app.sync_portal_tasks_with_kanban,
        }
        portal_app.DATA_DIR = self.root / "data"
        portal_app.UPLOAD_DIR = portal_app.DATA_DIR / "uploads"
        portal_app.DOCUMENTS_DIR = portal_app.DATA_DIR / "documents"
        portal_app.IN_REVIEW_DIR = portal_app.DOCUMENTS_DIR / "In Review"
        portal_app.DB_PATH = portal_app.DATA_DIR / "portal.db"
        portal_app.PORTAL_KANBAN_DB = self.root / "kanban.db"
        portal_app.DATA_DIR.mkdir(parents=True)
        portal_app.DOCUMENTS_DIR.mkdir(parents=True)
        portal_app.IN_REVIEW_DIR.mkdir(parents=True)
        portal_app.init_db()
        portal_app.bootstrap_admin_user()
        portal_app.sync_portal_tasks_with_kanban = lambda: None

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(portal_app, name, value)
        self.tmp.cleanup()

    def research_task(self, title="Quality report"):
        task_id = portal_app.create_portal_task(
            title=title,
            description="Build a threat intelligence report.",
            priority=5,
            requested_by="tester",
            assignee="tester",
            worker_profile="default",
            task_type="research",
            research_workflow="threat-intel",
            document_category="Threat Reports",
        )
        return portal_app.fetch_portal_task(task_id)

    def rich_report(self):
        return """
# Threat Intelligence Report

## 1. Executive Summary
Observed intrusion activity requires immediate defensive validation. Confidence: medium.

| Field | Value |
| --- | --- |
| Report ID | RPT-TR-2026-999 |
| TLP | CLEAR |

## 2. Intelligence Requirement
Assess exposure, impacted sectors, and defensive actions.

## 3. Source Review and Confidence
Sources include vendor reporting, telemetry review, and public advisories.

## 4. Key Findings
- Attackers used credential access and command execution.
- Activity maps to enterprise intrusion tradecraft.

## 5. Threat Context
The campaign uses remote access tooling and phishing.

## 6. Detection and Hunting
```kusto
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe")
| where ProcessCommandLine has_any ("DownloadString", "Invoke-WebRequest")
```

```sigma
title: Suspicious PowerShell Download
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: DownloadString
  condition: selection
```

## 7. Recommendations
Harden identity controls, monitor process telemetry, and review egress.

## 8. References
- https://example.invalid/report

## Indicators of Compromise
| Type | Value | Confidence |
| --- | --- | --- |
| domain | evil.example | medium |
| ipv4 | 203.0.113.7 | medium |

## MITRE ATT&CK Mapping
| Technique | Name |
| --- | --- |
| T1059 | Command and Scripting Interpreter |
"""

    def test_report_quality_score_rewards_complete_raiccoon_report(self):
        task = self.research_task()
        score = portal_app.score_report_quality(task, self.rich_report())
        self.assertEqual(score["score"], 100)
        self.assertEqual(score["grade"], "ready")
        self.assertTrue(score["pass_gate"])
        self.assertIn("Executive summary", score["passed_checks"])
        self.assertFalse(score["missing_required"])

    def test_report_quality_accepts_vulnerability_observables_without_exploit_iocs(self):
        task = self.research_task("Vulnerability report")
        portal_app.execute(
            "UPDATE portal_tasks SET document_category = ?, research_workflow = ? WHERE id = ?",
            ["Vulnerabilities", "threat-intel", task["id"]],
        )
        task = portal_app.fetch_portal_task(task["id"])
        report = self.rich_report() + """

## 9. Vulnerability Metadata
| Field | Value |
| --- | --- |
| CVE | CVE-2026-9999 |
| Affected Product | Example exposed appliance |

## 10. Exposure and Observable Artifacts
| Observable | Value | Use |
| --- | --- | --- |
| CVE | CVE-2026-9999 | Vulnerability tracking and patch validation |
| Product | Example exposed appliance | Asset inventory scoping |
| Exploit IOCs | No known public exploit infrastructure or attacker-owned indicators were available at publication. | Treat absence of IOCs as a source limitation, not as evidence of safety. |
"""
        score = portal_app.score_report_quality(task, report)
        self.assertEqual(score["score"], 100)
        self.assertEqual(score["grade"], "ready")
        self.assertFalse(score["missing_required"])

    def test_report_quality_accepts_numbered_recommendations_after_normalization(self):
        task = self.research_task("Malware report")
        portal_app.execute(
            "UPDATE portal_tasks SET document_category = ?, research_workflow = ? WHERE id = ?",
            ["Malware Analysis", "malware-analysis", task["id"]],
        )
        task = portal_app.fetch_portal_task(task["id"])
        report = self.rich_report().replace("## 7. Recommendations\nHarden identity controls, monitor process telemetry, and review egress.\n\n", "") + """

## 9. Static Analysis
Sample metadata, strings, imports, hash metadata, capa clues, and section layout were reviewed for each uploaded sample.

## 10. Code Analysis
GhidraMCP/Ghidra code analysis reviewed function sub_401000, xref 0x401050, and recovered config parsing behavior from decompiled snippets.

## 11. Dynamic Analysis
RAIccoon Local Sandbox dynamic analysis produced sandbox process, registry, filesystem, and network flow telemetry for all samples.

## 12. Process Tree and Execution Chain
Parent process launched a suspicious child process.

- 14. Recommendations
| Priority | Action |
| --- | --- |
| High | Isolate affected hosts and rotate exposed credentials. |
"""
        score = portal_app.score_report_quality(task, report)
        self.assertEqual(score["score"], 100)
        self.assertNotIn("Recommendations", score["missing_required"])

    def test_report_quality_score_flags_thin_missing_sections(self):
        task = self.research_task()
        score = portal_app.score_report_quality(task, "# Notes\n\nShort summary only.")
        self.assertLess(score["score"], 50)
        self.assertEqual(score["grade"], "needs_work")
        self.assertFalse(score["pass_gate"])
        self.assertIn("Executive summary", score["missing_required"])
        self.assertIn("Detection or hunt query", score["missing_required"])

    def test_board_payload_includes_quality_score_from_report_bundle(self):
        task = self.research_task()
        bundle = portal_app.report_bundle_dir_for_task(task)
        bundle.mkdir(parents=True)
        (bundle / "report.md").write_text(self.rich_report(), encoding="utf-8")

        payload = portal_app.task_board_payload(task["id"])
        serialized = payload["tasks"][0]
        self.assertIn("report_quality", serialized)
        self.assertGreaterEqual(serialized["report_quality"]["score"], 85)

    def test_board_payload_active_only_excludes_archived_qa_noise(self):
        task = self.research_task("Historical accepted report")
        portal_app.execute(
            "UPDATE portal_tasks SET status = 'accepted', last_result = 'historical summary only' WHERE id = ?",
            [task["id"]],
        )

        payload = portal_app.task_board_payload(task["id"])
        self.assertEqual(payload["visible_task_count"], 0)
        self.assertEqual(payload["analytics"]["qa_failing_count"], 0)

    def test_acceptance_requires_report_quality_gate_for_research_tasks(self):
        task = self.research_task()
        review_pdf = portal_app.IN_REVIEW_DIR / "thin.pdf"
        review_pdf.write_bytes(b"%PDF-1.4\n%thin\n")
        portal_app.execute(
            "UPDATE portal_tasks SET status = 'in_review', review_document_path = ?, review_notes = 'reviewed', review_signoff = 1 WHERE id = ?",
            [str(review_pdf), task["id"]],
        )
        updated = portal_app.fetch_portal_task(task["id"])

        ok, reason = portal_app.validate_task_transition(updated, "accepted")
        self.assertFalse(ok)
        self.assertIn("quality gate", reason.lower())

    def test_auto_publish_defers_sub_90_reports_to_review(self):
        task = self.research_task()
        review_pdf = portal_app.IN_REVIEW_DIR / "sub90.pdf"
        review_pdf.write_bytes(b"%PDF-1.4\n%sub90\n")
        sub90_report = self.rich_report().replace(
            "\n## 8. References\n- https://example.invalid/report\n",
            "",
        ).replace(
            "\n## MITRE ATT&CK Mapping\n| Technique | Name |\n| --- | --- |\n| T1059 | Command and Scripting Interpreter |\n",
            "",
        )
        bundle = portal_app.report_bundle_dir_for_task(task)
        bundle.mkdir(parents=True)
        (bundle / "report.md").write_text(sub90_report, encoding="utf-8")
        portal_app.execute(
            "UPDATE portal_tasks SET status = 'in_progress', review_document_path = ? WHERE id = ?",
            [str(review_pdf), task["id"]],
        )

        updated = portal_app.auto_publish_completed_task(task["id"], actor="test")
        quality = portal_app.task_report_quality(updated)

        self.assertLess(quality["score"], portal_app.REPORT_AUTO_PUBLISH_MIN_SCORE)
        self.assertEqual(updated["status"], "in_review")
        self.assertEqual(updated["final_document_path"], "")
        history = portal_app.fetch_task_history(task["id"])
        self.assertTrue(any(item["event_type"] == "auto_publish_deferred" for item in history))

    def test_opencti_dashboard_summarizes_hygiene_uploads_and_curation_queue(self):
        audit_dir = self.root / "opencti-audit"
        audit_dir.mkdir()
        (audit_dir / "latest-opencti-hygiene-audit.json").write_text(json.dumps({
            "generated_at": "2026-06-16T02:23:53+00:00",
            "connectors": [{"name": "MITRE ATT&CK", "active": True}, {"name": "Broken", "active": False}],
            "counts": {"reports": 764, "labels": 4356},
            "hygiene": {"duplicate_report_candidates": 0, "label_normalization_candidates": 42},
        }), encoding="utf-8")
        (audit_dir / "latest-opencti-cleanup-apply.json").write_text(json.dumps({
            "generated_at": "2026-06-16T02:24:00+00:00",
            "results": [
                {"status": "deleted", "action": "delete_label"},
                {"status": "skipped", "action": "skip_label", "value": "1-2-3-4", "reason": "no exact IPv4-Addr observable found"},
            ],
        }), encoding="utf-8")
        state_path = self.root / "uploaded-state.json"
        state_path.write_text(json.dumps({
            "last_run_at": "2026-06-16T02:32:50+00:00",
            "uploaded": {"reports/example": {"opencti_id": "abc", "report_id": "RPT-TR-2026-001"}},
        }), encoding="utf-8")

        summary = portal_app.opencti_dashboard_summary(audit_dir=audit_dir, upload_state_path=state_path)
        self.assertEqual(summary["reports"], 764)
        self.assertEqual(summary["uploaded_reports"], 1)
        self.assertEqual(summary["active_connectors"], 1)
        self.assertEqual(summary["cleanup_deleted"], 1)
        self.assertEqual(summary["curation_queue"][0]["value"], "1-2-3-4")

    def test_queue_opencti_upload_tasks_creates_idempotent_private_work_items(self):
        kit = self.root / "analyst-kit"
        artifact = kit / "build" / "registry" / "report-registry.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({
            "schema_version": 1,
            "generated_at": "2026-06-16T04:15:00+00:00",
            "summary": {"total_reports": 3, "published_reports": 3},
            "reports": [
                {"report_id": "RPT-TR-2026-001", "title": "Needs Upload", "status": "published", "final_pdf_path": "reports/threat-reports/RPT-TR-2026-001_needs/final/RPT-TR-2026-001_needs.pdf", "source_path": "reports/threat-reports/RPT-TR-2026-001_needs/report.md"},
                {"report_id": "RPT-MA-2026-002", "title": "Already Uploaded", "status": "published", "final_pdf_path": "reports/malware-analysis/RPT-MA-2026-002_done/final/RPT-MA-2026-002_done.pdf", "opencti_id": "report--abc"},
                {"report_id": "RPT-TR-2026-003", "title": "No PDF Yet", "status": "review", "has_final_pdf": False},
            ],
        }), encoding="utf-8")
        state_path = self.root / "uploaded-state.json"
        state_path.write_text(json.dumps({"uploaded": {"reports/done": {"report_id": "RPT-MA-2026-002", "opencti_id": "report--abc"}}}), encoding="utf-8")

        first = portal_app.queue_opencti_upload_tasks(kit, upload_state_path=state_path, requested_by="tester")
        second = portal_app.queue_opencti_upload_tasks(kit, upload_state_path=state_path, requested_by="tester")

        self.assertEqual(first["queued_count"], 1)
        self.assertEqual(first["skipped_uploaded_count"], 1)
        self.assertEqual(first["skipped_not_ready_count"], 1)
        self.assertEqual(second["queued_count"], 0)
        self.assertEqual(second["skipped_existing_count"], 1)
        task = portal_app.fetch_portal_task(first["queued_task_ids"][0])
        self.assertEqual(task["source_page"], "opencti-upload")
        self.assertIn("Report ID: `RPT-TR-2026-001`", task["description"])
        self.assertIn("make opencti-upload REPORT=reports/threat-reports/RPT-TR-2026-001_needs", task["description"])

    def test_queue_opencti_upload_route_requires_auth(self):
        unauth = portal_app.queue_opencti_upload_route(DummyRequest(authenticated=False))
        self.assertEqual(unauth.status_code, 401)

    def test_analyst_report_registry_counts_reports_iocs_and_detections(self):
        kit = self.root / "analyst-kit"
        report = kit / "reports" / "malware-analysis" / "RPT-MA-2026-001_example"
        (report / "detections" / "kql").mkdir(parents=True)
        (report / "final").mkdir()
        (report / "metadata.yaml").write_text("report_id: RPT-MA-2026-001\ntitle: Example\nstatus: published\n", encoding="utf-8")
        (report / "report.md").write_text("# Example\n", encoding="utf-8")
        (report / "iocs.csv").write_text("type,value\ndomain,evil.example\nipv4,203.0.113.10\n", encoding="utf-8")
        (report / "detections" / "kql" / "hunt.kql").write_text("DeviceProcessEvents", encoding="utf-8")
        (report / "final" / "RPT-MA-2026-001_example.pdf").write_bytes(b"pdf")

        registry = portal_app.analyst_report_registry(kit)
        self.assertEqual(registry["total_reports"], 1)
        self.assertEqual(registry["published_reports"], 1)
        self.assertEqual(registry["ioc_count"], 2)
        self.assertEqual(registry["detection_count"], 1)
        self.assertEqual(registry["reports"][0]["report_id"], "RPT-MA-2026-001")

    def test_analyst_report_registry_prefers_generated_registry_artifact(self):
        kit = self.root / "analyst-kit"
        artifact = kit / "build" / "registry" / "report-registry.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({
            "schema_version": 1,
            "generated_at": "2026-06-16T03:30:00+00:00",
            "summary": {
                "total_reports": 2,
                "published_reports": 1,
                "ioc_count": 7,
                "detection_count": 4,
                "missing_final_pdf": 1,
                "duplicate_report_ids": ["RPT-MA-2026-001"],
            },
            "reports": [
                {"report_id": "RPT-MA-2026-001", "title": "From Artifact", "status": "published", "final_pdf_path": "reports/a/final.pdf", "ioc_count": 7, "detection_count": 4}
            ],
        }), encoding="utf-8")

        registry = portal_app.analyst_report_registry(kit)
        self.assertEqual(registry["total_reports"], 2)
        self.assertEqual(registry["published_reports"], 1)
        self.assertEqual(registry["ioc_count"], 7)
        self.assertEqual(registry["detection_count"], 4)
        self.assertEqual(registry["missing_final_pdf"], 1)
        self.assertEqual(registry["duplicate_report_ids"], ["RPT-MA-2026-001"])
        self.assertEqual(registry["reports"][0]["title"], "From Artifact")
        self.assertEqual(registry["source_file"], str(artifact))

    def test_analyst_detection_library_filters_registry_detections(self):
        kit = self.root / "analyst-kit"
        artifact = kit / "build" / "registry" / "report-registry.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({
            "schema_version": 1,
            "generated_at": "2026-06-16T03:35:00+00:00",
            "summary": {"detection_count": 2, "detections_by_type": {"kql": 1, "sigma": 1}},
            "detections": [
                {"report_id": "RPT-MA-2026-001", "report_title": "Malware", "detection_type": "kql", "file_path": "reports/a/detections/kql/hunt.kql", "attack_techniques": ["T1059"], "telemetry_source": "Endpoint process telemetry", "target_platform": "Windows", "status": "reviewed"},
                {"report_id": "RPT-VTI-2026-002", "report_title": "Cloud", "detection_type": "sigma", "file_path": "reports/b/detections/sigma/rule.yml", "attack_techniques": ["T1190"], "telemetry_source": "Web logs", "target_platform": "Linux", "status": "draft"},
            ],
        }), encoding="utf-8")

        library = portal_app.analyst_detection_library(kit, query="T1059 windows")
        self.assertEqual(library["total_detections"], 2)
        self.assertEqual(library["filtered_count"], 1)
        self.assertEqual(library["detections"][0]["report_id"], "RPT-MA-2026-001")
        self.assertEqual(library["detections_by_type"], {"kql": 1, "sigma": 1})
        self.assertEqual(library["source_file"], str(artifact))

    def test_detections_data_route_requires_auth_and_supports_query(self):
        kit = self.root / "analyst-kit"
        artifact = kit / "build" / "registry" / "report-registry.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({
            "schema_version": 1,
            "summary": {"detection_count": 1, "detections_by_type": {"kql": 1}},
            "detections": [
                {"report_id": "RPT-MA-2026-001", "report_title": "Malware", "detection_type": "kql", "file_path": "reports/a/detections/kql/hunt.kql", "attack_techniques": ["T1059"], "telemetry_source": "Endpoint process telemetry", "target_platform": "Windows", "status": "reviewed"},
            ],
        }), encoding="utf-8")
        original = getattr(portal_app, "analyst_kit_root")
        setattr(portal_app, "analyst_kit_root", lambda: kit)
        try:
            unauth = portal_app.detections_data(DummyRequest(authenticated=False), q="T1059")
            self.assertEqual(unauth.status_code, 401)
            response = portal_app.detections_data(DummyRequest(), q="T1059 windows")
        finally:
            setattr(portal_app, "analyst_kit_root", original)

        payload = json.loads(response.body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["filtered_count"], 1)
        self.assertEqual(payload["detections"][0]["report_id"], "RPT-MA-2026-001")

    def test_daily_intel_brief_prioritizes_private_operator_actions(self):
        opencti = {
            "cleanup_skipped": 4,
            "duplicate_report_candidates": 2,
            "inactive_connectors": ["Broken Feed"],
            "curation_queue": [{"value": "1-2-3-4", "reason": "no exact IPv4-Addr observable found"}],
        }
        registry = {
            "reports": [
                {"report_id": "RPT-TR-2026-001", "title": "Needs PDF", "status": "review", "has_final_pdf": False, "ioc_count": 2, "detection_count": 0},
                {"report_id": "RPT-MA-2026-002", "title": "Ready", "status": "published", "has_final_pdf": True, "ioc_count": 6, "detection_count": 3},
            ]
        }

        brief = portal_app.build_daily_intel_brief(opencti, registry, generated_at="2026-06-16T12:00:00+00:00")

        self.assertEqual(brief["visibility"], "private_internal")
        self.assertIn("Needs PDF", brief["reports_needing_review"][0]["title"])
        self.assertIn("Broken Feed", brief["opencti_hygiene_drift"][0])
        self.assertGreaterEqual(len(brief["recommended_actions"]), 3)
        self.assertTrue(any("curation" in action.lower() for action in brief["recommended_actions"]))

    def test_write_latest_daily_intel_brief_writes_portal_artifact(self):
        brief = {"generated_at": "2026-06-16T12:00:00+00:00", "visibility": "private_internal", "recommended_actions": ["Review queue"]}

        path = portal_app.write_latest_daily_intel_brief(brief)

        self.assertTrue(path.exists())
        self.assertEqual(path, portal_app.DATA_DIR / "intel-ops" / "latest-daily-brief.json")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["visibility"], "private_internal")

    def test_private_client_profiles_are_stored_for_internal_readiness(self):
        client_id = portal_app.create_client_profile(
            org_alias="Manufacturing Alpha",
            sector="manufacturing",
            priority_requirements="Ransomware, OT downtime",
            technologies="Windows, PLCs, VPN",
            delivery_cadence="weekly",
            allowed_tlp="TLP:AMBER",
            opencti_collections="Ransomware watchlist",
            notes="Private pilot engagement",
        )

        profiles = portal_app.client_profiles()
        self.assertEqual(client_id, profiles[0]["id"])
        self.assertEqual(profiles[0]["org_alias"], "Manufacturing Alpha")
        self.assertEqual(profiles[0]["allowed_tlp"], "TLP:AMBER")
        self.assertEqual(profiles[0]["detections_delivered"], 0)

    def test_tasks_can_be_associated_with_private_client_profiles(self):
        client_id = portal_app.create_client_profile(
            org_alias="Manufacturing Alpha",
            sector="manufacturing",
            priority_requirements="Ransomware, OT downtime",
            technologies="Windows, PLCs, VPN",
            delivery_cadence="weekly",
            allowed_tlp="TLP:AMBER",
            opencti_collections="Ransomware watchlist",
            notes="Private pilot engagement",
        )
        task = self.research_task("Client scoped report")

        portal_app.update_task_client_association(task["id"], client_id, actor="tester")

        updated = portal_app.fetch_portal_task(task["id"])
        self.assertEqual(updated["client_profile_id"], client_id)
        payload = portal_app.task_board_payload(task["id"])
        serialized = payload["tasks"][0]
        self.assertEqual(serialized["client_profile"]["id"], client_id)
        self.assertEqual(serialized["client_profile"]["org_alias"], "Manufacturing Alpha")
        profiles = portal_app.client_profiles()
        self.assertEqual(profiles[0]["active_reports"], 1)

    def test_task_client_association_route_requires_auth_and_rejects_unknown_client(self):
        task = self.research_task("Route scoped report")
        unauth = portal_app.update_task_client_route(DummyRequest(authenticated=False), task["id"], client_profile_id=0)
        self.assertEqual(unauth.status_code, 303)

        response = portal_app.update_task_client_route(DummyRequest(), task["id"], client_profile_id=9999)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Client profile not found", response.body.decode("utf-8"))

    def test_opencti_curation_candidates_import_as_idempotent_private_tasks(self):
        audit_dir = self.root / "opencti-audit"
        audit_dir.mkdir()
        (audit_dir / "latest-opencti-cleanup-candidates.json").write_text(json.dumps({
            "schema_version": 1,
            "generated_at": "2026-06-16T12:00:00+00:00",
            "summary": {"duplicate_reports": 1},
            "candidates": [{
                "candidate_id": "opencti-curation-dupe-1",
                "candidate_type": "duplicate_report_review",
                "category": "duplicate_report_review",
                "severity": "high",
                "title": "Review duplicate report title: same report",
                "rationale": "Two OpenCTI reports share a normalized title.",
                "proposed_action": "merge_proposal",
                "safe_mode": True,
                "source_artifact": "latest-opencti-hygiene-audit.json",
                "opencti_object_ids": ["report--1", "report--2"],
                "recommended_action": "Compare source metadata before merge/delete.",
            }],
        }), encoding="utf-8")

        summary = portal_app.opencti_dashboard_summary(audit_dir=audit_dir, upload_state_path=self.root / "missing-state.json")
        self.assertEqual(summary["curation_candidate_count"], 1)
        self.assertEqual(summary["curation_queue"][0]["candidate_id"], "opencti-curation-dupe-1")

        first = portal_app.import_opencti_curation_candidates(audit_dir=audit_dir, requested_by="tester")
        second = portal_app.import_opencti_curation_candidates(audit_dir=audit_dir, requested_by="tester")

        self.assertEqual(first["imported_count"], 1)
        self.assertEqual(second["imported_count"], 0)
        self.assertEqual(second["skipped_existing_count"], 1)
        task = portal_app.fetch_portal_task(first["imported_task_ids"][0])
        self.assertEqual(task["source_page"], "opencti-curation")
        self.assertIn("Candidate ID: `opencti-curation-dupe-1`", task["description"])
        self.assertIn("Tags: opencti-curation", task["description"])

    def test_client_engagement_export_and_brief_include_matching_reports_and_detections(self):
        kit = self.root / "kit"
        artifact = kit / "build" / "registry" / "report-registry.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({
            "summary": {"total_reports": 1, "published_reports": 1, "ioc_count": 2, "detection_count": 1},
            "reports": [{"report_id": "RPT-TR-2026-010", "title": "Manufacturing ransomware VPN activity", "status": "published", "has_final_pdf": True, "ioc_count": 2, "detection_count": 1}],
            "detections": [{"report_id": "RPT-TR-2026-010", "detection_type": "kql", "file_path": "detections/kql/vpn.kql"}],
        }), encoding="utf-8")
        client_id = portal_app.create_client_profile(
            org_alias="Manufacturing Alpha",
            sector="manufacturing",
            priority_requirements="ransomware vpn",
            technologies="Windows VPN",
        )

        export = portal_app.client_engagement_export(client_id, kit)
        brief = portal_app.build_client_brief(client_id, kit)

        self.assertEqual(export["summary"]["report_count"], 1)
        self.assertEqual(export["summary"]["detection_count"], 1)
        self.assertIn("Manufacturing Alpha", brief["executive_summary"])
        self.assertTrue(any("detection" in item.lower() for item in brief["recommended_actions"]))

    def test_registry_remediation_queue_creates_idempotent_gap_tasks(self):
        kit = self.root / "kit"
        artifact = kit / "build" / "registry" / "report-registry.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({
            "summary": {"total_reports": 3, "missing_final_pdf": 1, "duplicate_report_ids": ["RPT-TR-2026-001"]},
            "reports": [
                {"report_id": "RPT-TR-2026-001", "title": "Duplicate A", "path": "reports/a", "has_final_pdf": True},
                {"report_id": "RPT-TR-2026-001", "title": "Duplicate B", "path": "reports/b", "has_final_pdf": True},
                {"report_id": "RPT-TR-2026-002", "title": "Missing PDF", "path": "reports/c", "has_final_pdf": False, "category": "Threat Reports"},
            ],
        }), encoding="utf-8")

        first = portal_app.queue_registry_remediation_tasks(kit, requested_by="tester")
        second = portal_app.queue_registry_remediation_tasks(kit, requested_by="tester")

        self.assertEqual(first["created_count"], 2)
        self.assertEqual(second["created_count"], 0)
        self.assertEqual(second["skipped_existing_count"], 2)
        task = portal_app.fetch_portal_task(first["created_task_ids"][0])
        self.assertEqual(task["source_page"], "registry-remediation")

    def test_opencti_reconcile_upload_results_writes_task_history_once(self):
        state_path = self.root / "upload-state.json"
        state_path.write_text(json.dumps({"uploaded": {"reports/example": {"report_id": "RPT-TR-2026-777", "opencti_id": "report--777"}}}), encoding="utf-8")
        task_id = portal_app.create_portal_task(
            title="OpenCTI upload: Example",
            description="- Report ID: `RPT-TR-2026-777`",
            priority=5,
            requested_by="tester",
            assignee="analyst",
            worker_profile="default",
            source_page="opencti-upload",
        )

        first = portal_app.reconcile_opencti_upload_results(state_path, actor="tester")
        second = portal_app.reconcile_opencti_upload_results(state_path, actor="tester")

        self.assertEqual(first["reconciled_count"], 1)
        self.assertEqual(second["reconciled_count"], 0)
        history = portal_app.fetch_all("SELECT * FROM portal_task_history WHERE task_id = ? AND event_type = 'opencti_upload_reconciled'", [task_id])
        self.assertEqual(len(history), 1)

    def test_admin_routes_enforce_rbac_and_audit_exports(self):
        non_admin = DummyRequest()
        non_admin.session["role"] = "user"
        forbidden = portal_app.queue_opencti_upload_route(non_admin)
        self.assertEqual(forbidden.status_code, 403)

        admin = DummyRequest()
        portal_app.add_audit_log("tester", "unit_test", "thing", "1", "detail")
        exported = portal_app.export_audit_logs(admin)
        payload = json.loads(exported.body.decode("utf-8"))
        self.assertEqual(payload["export"], "portal_audit_log")
        self.assertEqual(payload["rows"][0]["action"], "unit_test")

    def test_build_opencti_landscape_summary_counts_entities_and_map_points(self):
        reports = [
            {
                "name": "Threat round-up",
                "published": "2026-06-18T05:41:52.250Z",
                "report_types": ["threat-report"],
                "objects": {
                    "edges": [
                        {"node": {"entity_type": "Threat-Actor", "representative": {"main": "APT28"}}},
                        {"node": {"entity_type": "Threat-Actor", "representative": {"main": "APT28"}}},
                        {"node": {"entity_type": "Sector", "representative": {"main": "Technology"}}},
                        {"node": {"entity_type": "Malware", "representative": {"main": "Cobalt Strike"}}},
                        {"node": {"entity_type": "Vulnerability", "representative": {"main": "CVE-2026-1234"}}},
                        {"node": {"entity_type": "Country", "representative": {"main": "United States of America"}, "latitude": 38.0, "longitude": -97.0}},
                    ]
                },
            },
            {
                "name": "Follow-on campaign update",
                "published": "2026-06-17T02:10:00.000Z",
                "report_types": ["threat-report"],
                "objects": {
                    "edges": [
                        {"node": {"entity_type": "Threat-Actor", "representative": {"main": "APT28"}}},
                        {"node": {"entity_type": "Organization", "representative": {"main": "Example Telecom"}}},
                        {"node": {"entity_type": "Malware", "representative": {"main": "Cobalt Strike"}}},
                        {"node": {"entity_type": "Country", "representative": {"main": "United States of America"}, "latitude": 38.0, "longitude": -97.0}},
                    ]
                },
            },
        ]

        summary = portal_app.build_opencti_landscape_summary(reports, generated_at="2026-06-18T06:00:00+00:00")

        self.assertEqual(summary["report_count"], 2)
        self.assertEqual(summary["threats"][0]["name"], "APT28")
        self.assertEqual(summary["threats"][0]["count"], 2)
        self.assertEqual(summary["victims"][0]["count"], 1)
        self.assertEqual(summary["malware"][0]["name"], "Cobalt Strike")
        self.assertEqual(summary["vulnerabilities"][0]["name"], "CVE-2026-1234")
        self.assertEqual(summary["countries"][0]["name"], "United States of America")
        self.assertEqual(summary["country_map_points"][0]["name"], "United States of America")
        self.assertGreater(summary["country_map_points"][0]["x"], 0)
        self.assertGreater(summary["country_map_points"][0]["radius"], 0)

    def test_opencti_threat_landscape_summary_falls_back_to_cache(self):
        cache_path = portal_app.opencti_landscape_cache_path()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({
            "generated_at": "2026-06-18T06:00:00+00:00",
            "source": "live",
            "window_days": 90,
            "report_count": 1,
            "latest_report_published": "2026-06-18T05:41:52.250Z",
            "threats": [{"name": "APT28", "count": 1, "entity_types": ["Threat-Actor"], "sample_reports": ["Threat round-up"]}],
            "victims": [],
            "malware": [],
            "vulnerabilities": [],
            "countries": [],
            "country_map_points": [],
            "sample_reports": [{"name": "Threat round-up", "published": "2026-06-18T05:41:52.250Z", "report_types": ["threat-report"]}],
        }), encoding="utf-8")
        original_fetch = portal_app.fetch_opencti_recent_reports
        portal_app.fetch_opencti_recent_reports = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("OpenCTI offline"))
        try:
            summary = portal_app.opencti_threat_landscape_summary(force_refresh=True)
        finally:
            portal_app.fetch_opencti_recent_reports = original_fetch

        self.assertEqual(summary["source"], "live")
        self.assertEqual(summary["threats"][0]["name"], "APT28")
        self.assertIn("warning", summary)
        self.assertIn("OpenCTI offline", summary["warning"])


if __name__ == "__main__":
    unittest.main()
