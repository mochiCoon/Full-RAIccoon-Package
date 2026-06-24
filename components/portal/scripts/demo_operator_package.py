#!/usr/bin/env python3
"""Safe offline operator demo harness for the Your Organization portal.

This script seeds a temporary portal database and report library with synthetic
records, exercises the dashboard/task/client/document workflow helpers, and
prints a compact talk-track transcript. It does not touch live portal state,
OpenCTI, analyst-kit artifacts, or credentials.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path
from types import ModuleType
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_PATH = REPO_ROOT / "app.py"
GUIDED_UI_PATH = [
    "/dashboard",
    "/tasks?status=in_review",
    "/research",
    "/documents",
    "/clients",
    "/security",
]


def load_portal_app() -> ModuleType:
    spec = importlib.util.spec_from_file_location("portal_app_demo_operator", APP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load portal app from {APP_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


portal_app = cast(Any, load_portal_app())


def patch_runtime(root: Path) -> dict[str, Any]:
    originals = {
        "DATA_DIR": portal_app.DATA_DIR,
        "UPLOAD_DIR": portal_app.UPLOAD_DIR,
        "DOCUMENTS_DIR": portal_app.DOCUMENTS_DIR,
        "IN_REVIEW_DIR": portal_app.IN_REVIEW_DIR,
        "DB_PATH": portal_app.DB_PATH,
        "PORTAL_KANBAN_DB": portal_app.PORTAL_KANBAN_DB,
        "RAICCOON_PORTABLE_ZIP": portal_app.RAICCOON_PORTABLE_ZIP,
        "sync_portal_tasks_with_kanban": portal_app.sync_portal_tasks_with_kanban,
    }
    portal_app.DATA_DIR = root / "data"
    portal_app.UPLOAD_DIR = portal_app.DATA_DIR / "uploads"
    portal_app.DOCUMENTS_DIR = portal_app.DATA_DIR / "Reports"
    portal_app.IN_REVIEW_DIR = portal_app.DOCUMENTS_DIR / "In Review"
    portal_app.DB_PATH = portal_app.DATA_DIR / "portal.db"
    portal_app.PORTAL_KANBAN_DB = root / "kanban.db"
    portal_app.RAICCOON_PORTABLE_ZIP = root / "missing-portable.zip"
    portal_app.sync_portal_tasks_with_kanban = lambda: None
    portal_app.DATA_DIR.mkdir(parents=True, exist_ok=True)
    portal_app.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    portal_app.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    portal_app.IN_REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    return originals


def restore_runtime(originals: dict[str, Any]) -> None:
    for name, value in originals.items():
        setattr(portal_app, name, value)


def write_fake_pdf(path: Path, title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Small syntactically recognizable PDF placeholder. The portal's final-doc
    # library gate is filename/category based; no live customer content is used.
    payload = f"%PDF-1.4\n% Synthetic demo PDF: {title}\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
    path.write_bytes(payload.encode("utf-8"))


def rich_report(title: str) -> str:
    return f"""# {title}

## 1. Executive Summary
Synthetic private-client intelligence indicates a plausible phishing-to-cloud-access intrusion path. Confidence: medium.

## 2. Intelligence Requirement
Assess likely exposure, priority defensive actions, detection coverage, and reporting deliverables.

## 3. Source Review and Confidence
This offline demo uses seeded, synthetic source material only. No live OpenCTI, customer, or credential data is touched.

## 4. Key Findings
- Operators need a single intake-to-delivery workflow.
- Detection and hunt outputs should be tied back to report IDs.
- Final PDFs should be separated from drafts and source bundles.

## 5. Threat Context
The scenario models credential theft, remote access, data staging, and follow-on detection engineering needs.

## 6. Detection and Hunting
```kusto
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe")
| where ProcessCommandLine has_any ("DownloadString", "Invoke-WebRequest")
```

```sigma
title: Synthetic Demo Suspicious Script Download
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: DownloadString
  condition: selection
```

## 7. Recommendations
Prioritize identity hardening, endpoint telemetry validation, egress review, and client-scoped follow-up tasks.

## 8. References
- https://example.invalid/rpt-demo

## Indicators of Compromise
| Type | Value | Confidence |
| --- | --- | --- |
| domain | demo-control.example | medium |
| ipv4 | 203.0.113.17 | medium |

## MITRE ATT&CK Mapping
| Technique | Name |
| --- | --- |
| T1059 | Command and Scripting Interpreter |
| T1078 | Valid Accounts |
"""


def insert_published_work(title: str, status: str, outlet: str, url: str, owner: str, tags: str) -> int:
    now = portal_app.now_utc().isoformat()
    with closing(portal_app.connect_db()) as connection:
        cursor = connection.execute(
            """
            INSERT INTO published_works (
                title, status, outlet, url, publication_date, due_date, owner,
                artifact_type, audience, tags, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'report', 'internal', ?, ?, ?, ?)
            """,
            [
                title,
                status,
                outlet,
                url,
                portal_app.date.today().isoformat(),
                "",
                owner,
                tags,
                "Synthetic offline demo record.",
                now,
                now,
            ],
        )
        connection.commit()
        return int(cursor.lastrowid or 0)


def seed_demo_state() -> dict[str, Any]:
    portal_app.init_db()
    portal_app.bootstrap_admin_user()

    client_id = portal_app.create_client_profile(
        org_alias="Client Atlas",
        sector="Financial services",
        priority_requirements="Cloud identity compromise; ransomware precursor activity; executive-ready weekly brief.",
        technologies="Microsoft 365, Entra ID, Defender, Sentinel, Okta, CrowdStrike",
        delivery_cadence="Weekly private intelligence brief; urgent detections as needed",
        allowed_tlp="TLP:AMBER",
        detections_delivered=7,
        opencti_collections="Synthetic Collection: Demo Executive Threat Briefs",
        notes="Synthetic client profile for safe demo walkthroughs only.",
    )

    tasks: dict[str, int] = {}
    tasks["review"] = portal_app.create_portal_task(
        title="Review client-ready cloud intrusion brief",
        description="QA the synthetic brief, verify detections and client recommendations, then approve for final PDF delivery.",
        priority=9,
        requested_by="demo-operator",
        assignee="demo-analyst",
        worker_profile="default",
        task_type="research",
        source_page="demo-harness",
        research_workflow="threat-intel",
        document_category="Executive Summaries",
        due_date=portal_app.date.today().isoformat(),
        sla_hours=24,
        acceptance_criteria="Final PDF is client-ready, detection references are present, and OpenCTI linkage is queued.",
    )
    tasks["blocked"] = portal_app.create_portal_task(
        title="Unblock OpenCTI upload reconciliation gap",
        description="Synthetic upload result is missing an OpenCTI external reference; operator needs to reconcile the registry state.",
        priority=8,
        requested_by="demo-operator",
        assignee="demo-analyst",
        worker_profile="default",
        task_type="general",
        source_page="demo-harness",
        due_date=portal_app.date.today().isoformat(),
        sla_hours=8,
        acceptance_criteria="Gap is represented as a task and can be resolved without touching live OpenCTI.",
    )
    tasks["accepted"] = portal_app.create_portal_task(
        title="Publish synthetic detection engineering package",
        description="SOC-ready Sigma/KQL package tied to the synthetic report and client profile.",
        priority=7,
        requested_by="demo-operator",
        assignee="demo-analyst",
        worker_profile="default",
        task_type="research",
        source_page="demo-harness",
        research_workflow="detection-engineering",
        document_category="Detection Engineering",
        acceptance_criteria="Detection package is linked to final PDF and published-work record.",
    )

    for task_id in tasks.values():
        portal_app.update_task_client_association(task_id, client_id, actor="demo-operator")

    final_pdf = portal_app.DOCUMENTS_DIR / "Executive Summaries" / "RPT-ES-2026-900_synthetic-cloud-intrusion-brief.pdf"
    detection_pdf = portal_app.DOCUMENTS_DIR / "Detection Engineering" / "RPT-DE-2026-901_synthetic-script-download-detections.pdf"
    write_fake_pdf(final_pdf, "Synthetic Cloud Intrusion Brief")
    write_fake_pdf(detection_pdf, "Synthetic Script Download Detections")

    review_bundle = portal_app.report_bundle_dir_for_task(portal_app.fetch_portal_task(tasks["review"]))
    review_bundle.mkdir(parents=True, exist_ok=True)
    (review_bundle / "report.md").write_text(rich_report("Synthetic Cloud Intrusion Brief"), encoding="utf-8")
    review_pdf = portal_app.IN_REVIEW_DIR / "RPT-ES-2026-900_synthetic-cloud-intrusion-brief_review.pdf"
    write_fake_pdf(review_pdf, "Synthetic Cloud Intrusion Brief Review Draft")

    published_id = insert_published_work(
        title="Synthetic Script Download Detection Package",
        status="published",
        outlet="Your Organization private document library",
        url=str(detection_pdf),
        owner="demo-operator",
        tags="demo,detection-engineering,client-atlas",
    )

    now = portal_app.now_utc().isoformat()
    old = (portal_app.now_utc() - portal_app.timedelta(hours=36)).isoformat()
    portal_app.execute(
        """
        UPDATE portal_tasks
        SET status = 'in_review', review_document_path = ?, updated_at = ?
        WHERE id = ?
        """,
        [str(review_pdf), now, tasks["review"]],
    )
    portal_app.execute(
        """
        UPDATE portal_tasks
        SET status = 'blocked', blocked_reason = ?, blocked_at = ?, updated_at = ?
        WHERE id = ?
        """,
        ["Waiting on synthetic OpenCTI upload reconciliation output.", now, old, tasks["blocked"]],
    )
    portal_app.execute(
        """
        UPDATE portal_tasks
        SET status = 'accepted', final_document_path = ?, published_work_id = ?, updated_at = ?
        WHERE id = ?
        """,
        [str(detection_pdf), published_id, now, tasks["accepted"]],
    )

    portal_app.add_task_history(tasks["review"], "demo_seeded", "demo-operator", "Synthetic review task seeded for guided walkthrough.", source="demo")
    portal_app.add_task_history(tasks["blocked"], "blocked", "demo-operator", "Synthetic OpenCTI reconciliation blocker created.", source="demo")
    portal_app.create_notification(
        "review",
        "Synthetic brief ready for review",
        "Client Atlas executive brief is staged in the offline review queue.",
        task_id=tasks["review"],
        notification_key="demo-review-ready",
    )
    portal_app.add_audit_log("demo-operator", "demo_seed", "operator_demo", "offline", "Seeded synthetic demo package in temporary state.")

    return {"client_id": client_id, "tasks": tasks, "final_pdf": str(final_pdf), "review_pdf": str(review_pdf)}


def build_demo_summary() -> dict[str, Any]:
    seed = seed_demo_state()
    board = portal_app.task_board_payload()
    workflow = portal_app.workflow_context("dashboard", board)
    summary = portal_app.dashboard_summary()
    docs = portal_app.report_document_categories()
    clients = portal_app.client_profiles()
    notifications = portal_app.fetch_notifications(unread_only=True, limit=5)
    focus = workflow.get("focus_queue", [])[:5]
    return {
        "seed": seed,
        "summary": summary,
        "board_analytics": board.get("analytics", {}),
        "workflow_status_line": workflow.get("status_line", ""),
        "focus_queue": [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "status": item.get("status_label"),
                "client": item.get("client"),
                "qa_state": item.get("qa_state"),
            }
            for item in focus
        ],
        "document_categories": [{"name": item["name"], "count": item["count"]} for item in docs],
        "clients": [{"org_alias": item["org_alias"], "sector": item["sector"], "active_reports": item["active_reports"]} for item in clients],
        "notifications": [{"title": item["title"], "task_id": item["task_id"]} for item in notifications],
        "guided_ui_path": GUIDED_UI_PATH,
        "safety": "Demo completed without touching live portal/OpenCTI state.",
    }


def print_transcript(summary: dict[str, Any]) -> None:
    print("Your Organization portal offline operator demo")
    print("=" * 48)
    print("\n[1] Seeded synthetic state")
    print(f"Client profile id: {summary['seed']['client_id']}")
    for key, task_id in summary["seed"]["tasks"].items():
        print(f"Task {key}: #{task_id}")

    print("\n[2] Dashboard and board signal")
    dash = summary["summary"]
    analytics = summary["board_analytics"]
    print(f"Open tasks: {dash['open_tasks']} | Final PDFs: {dash['document_count']} | Published works: {dash['published_count']}")
    print(
        "Board: "
        f"blocked={analytics.get('blocked_count', 0)}, "
        f"review={analytics.get('review_count', 0)}, "
        f"stale={analytics.get('stale_count', 0)}, "
        f"qa_failing={analytics.get('qa_failing_count', 0)}"
    )
    print(f"Workflow status: {summary['workflow_status_line']}")

    print("\n[3] Priority queue")
    for item in summary["focus_queue"]:
        print(f"#{item['id']} [{item['status']}] {item['title']} :: client={item['client'] or 'unassigned'} qa={item['qa_state'] or 'n/a'}")

    print("\n[4] Documents and client context")
    for item in summary["document_categories"]:
        print(f"{item['name']}: {item['count']} final PDF(s)")
    for client in summary["clients"]:
        print(f"Client {client['org_alias']} ({client['sector']}): {client['active_reports']} active report task(s)")

    print("\n[5] Guided UI path")
    for route in summary["guided_ui_path"]:
        print(f"- {route}")

    print("\n[6] Operator notifications")
    for item in summary["notifications"]:
        print(f"Task #{item['task_id']}: {item['title']}")

    print(f"\nSAFETY: {summary['safety']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a safe offline Your Organization portal operator demo.")
    parser.add_argument("--json", action="store_true", help="Print the demo summary as JSON instead of a transcript.")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="rpt-portal-demo-") as tmp:
        root = Path(tmp)
        originals = patch_runtime(root)
        try:
            summary = build_demo_summary()
            if args.json:
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print_transcript(summary)
        finally:
            restore_runtime(originals)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
