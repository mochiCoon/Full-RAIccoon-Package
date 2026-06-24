#!/usr/bin/env python3
"""Offline demo harness for the private intel-ops portal workflows.

This script uses a temporary portal database and synthetic analyst-kit/OpenCTI
artifacts. It does not mutate the live portal DB or production OpenCTI state.

Run from the repository root:
    .venv/bin/python scripts/demo_private_intel_ops.py
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
from textwrap import indent
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_PATH = REPO_ROOT / "app.py"


def load_app() -> Any:
    spec = importlib.util.spec_from_file_location("portal_app_demo", APP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load portal app from {APP_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(Any, module)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def print_block(title: str, payload: dict | list | str) -> None:
    print(f"\n=== {title} ===")
    if isinstance(payload, str):
        print(indent(payload, "  "))
    else:
        print(indent(json.dumps(payload, indent=2, sort_keys=True), "  "))


def build_demo_registry(kit_root: Path) -> Path:
    registry = {
        "schema_version": 1,
        "generated_at": "2026-06-16T12:00:00+00:00",
        "root": str(kit_root),
        "summary": {
            "total_reports": 4,
            "published_reports": 2,
            "missing_final_pdf": 1,
            "ioc_count": 14,
            "detection_count": 4,
            "duplicate_report_ids": ["RPT-TR-2026-099"],
            "detections_by_type": {"kql": 2, "sigma": 1, "spl": 1},
            "detections_by_status": {"production-ready": 3, "draft": 1},
        },
        "reports": [
            {
                "report_id": "RPT-TR-2026-010",
                "title": "Manufacturing VPN Ransomware Intrusion Readiness",
                "status": "published",
                "category": "threat-reports",
                "path": "reports/threat-reports/RPT-TR-2026-010_manufacturing-vpn-ransomware-readiness",
                "final_pdf_path": "reports/threat-reports/RPT-TR-2026-010_manufacturing-vpn-ransomware-readiness/final/RPT-TR-2026-010_manufacturing-vpn-ransomware-readiness.pdf",
                "has_final_pdf": True,
                "ioc_count": 8,
                "detection_count": 3,
            },
            {
                "report_id": "RPT-MA-2026-022",
                "title": "Credential Stealer Targeting M365 Admins",
                "status": "review",
                "category": "malware-analysis",
                "path": "reports/malware-analysis/RPT-MA-2026-022_credential-stealer-m365-admins",
                "final_pdf_path": "reports/malware-analysis/RPT-MA-2026-022_credential-stealer-m365-admins/final/RPT-MA-2026-022_credential-stealer-m365-admins.pdf",
                "has_final_pdf": True,
                "ioc_count": 6,
                "detection_count": 1,
            },
            {
                "report_id": "RPT-TR-2026-099",
                "title": "Duplicate Registry Entry A",
                "status": "published",
                "category": "threat-reports",
                "path": "reports/threat-reports/RPT-TR-2026-099_duplicate-a",
                "has_final_pdf": True,
                "ioc_count": 0,
                "detection_count": 0,
            },
            {
                "report_id": "RPT-TR-2026-099",
                "title": "Duplicate Registry Entry B Missing PDF",
                "status": "review",
                "category": "threat-reports",
                "path": "reports/threat-reports/RPT-TR-2026-099_duplicate-b",
                "has_final_pdf": False,
                "ioc_count": 0,
                "detection_count": 0,
            },
        ],
        "detections": [
            {
                "report_id": "RPT-TR-2026-010",
                "report_title": "Manufacturing VPN Ransomware Intrusion Readiness",
                "detection_type": "kql",
                "file_path": "detections/kql/vpn-followed-by-discovery.kql",
                "telemetry_source": "MDE DeviceNetworkEvents",
                "target_platform": "Windows",
                "status": "production-ready",
                "attack_techniques": ["T1133", "T1087"],
            },
            {
                "report_id": "RPT-TR-2026-010",
                "report_title": "Manufacturing VPN Ransomware Intrusion Readiness",
                "detection_type": "sigma",
                "file_path": "detections/sigma/ransomware-staging.yml",
                "telemetry_source": "EDR process telemetry",
                "target_platform": "Windows",
                "status": "production-ready",
                "attack_techniques": ["T1486"],
            },
            {
                "report_id": "RPT-TR-2026-010",
                "report_title": "Manufacturing VPN Ransomware Intrusion Readiness",
                "detection_type": "spl",
                "file_path": "detections/spl/vpn-then-enumeration.spl",
                "telemetry_source": "VPN + endpoint logs",
                "target_platform": "Splunk",
                "status": "production-ready",
                "attack_techniques": ["T1133", "T1087"],
            },
            {
                "report_id": "RPT-MA-2026-022",
                "report_title": "Credential Stealer Targeting M365 Admins",
                "detection_type": "kql",
                "file_path": "detections/kql/m365-token-theft.kql",
                "telemetry_source": "Entra ID sign-in logs",
                "target_platform": "M365",
                "status": "draft",
                "attack_techniques": ["T1528"],
            },
        ],
    }
    artifact = kit_root / "build" / "registry" / "report-registry.json"
    write_json(artifact, registry)
    return artifact


def build_demo_opencti_state(path: Path) -> None:
    write_json(
        path,
        {
            "uploaded": {
                "reports/threat-reports/RPT-TR-2026-010_manufacturing-vpn-ransomware-readiness": {
                    "report_id": "RPT-TR-2026-010",
                    "opencti_id": "report--demo-manufacturing-vpn",
                    "uploaded_at": "2026-06-16T12:10:00+00:00",
                }
            }
        },
    )


def build_demo_audit(audit_dir: Path) -> None:
    write_json(
        audit_dir / "latest-opencti-cleanup-candidates.json",
        {
            "schema_version": 1,
            "generated_at": "2026-06-16T12:20:00+00:00",
            "summary": {"duplicate_reports": 1},
            "candidates": [
                {
                    "candidate_id": "demo-opencti-dupe-report",
                    "candidate_type": "duplicate_report_review",
                    "category": "duplicate_report_review",
                    "severity": "high",
                    "title": "Review duplicate OpenCTI report objects for RPT-TR-2026-099",
                    "rationale": "Two OpenCTI report objects share a normalized report title.",
                    "proposed_action": "manual_review_before_merge_or_delete",
                    "safe_mode": True,
                    "source_artifact": "latest-opencti-hygiene-audit.json",
                    "opencti_object_ids": ["report--demo-a", "report--demo-b"],
                    "recommended_action": "Compare source metadata and keep the canonical Your Organization object.",
                }
            ],
        },
    )


def main() -> int:
    app = load_app()
    with tempfile.TemporaryDirectory(prefix="rpt-portal-demo-") as tmp_text:
        tmp = Path(tmp_text)
        data_dir = tmp / "portal-data"
        kit_root = tmp / "analyst-kit"
        audit_dir = tmp / "opencti-audit"
        upload_state = tmp / "uploaded-published-state.json"

        # Redirect the app module to temporary state so the demo is safe to run.
        app.DATA_DIR = data_dir
        app.UPLOAD_DIR = data_dir / "uploads"
        app.DOCUMENTS_DIR = data_dir / "documents"
        app.IN_REVIEW_DIR = app.DOCUMENTS_DIR / "In Review"
        app.DB_PATH = data_dir / "portal.db"
        app.PORTAL_KANBAN_DB = tmp / "kanban.db"
        app.sync_portal_tasks_with_kanban = lambda: None
        app.analyst_kit_root = lambda: kit_root
        app.opencti_audit_dir = lambda: audit_dir
        app.opencti_upload_state_path = lambda: upload_state

        app.DATA_DIR.mkdir(parents=True, exist_ok=True)
        app.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
        app.IN_REVIEW_DIR.mkdir(parents=True, exist_ok=True)
        app.init_db()
        registry_artifact = build_demo_registry(kit_root)
        build_demo_opencti_state(upload_state)
        build_demo_audit(audit_dir)

        client_id = app.create_client_profile(
            org_alias="Manufacturing Alpha",
            sector="manufacturing",
            priority_requirements="Ransomware, VPN abuse, discovery after remote access",
            technologies="Windows, Microsoft 365, VPN, Splunk",
            delivery_cadence="weekly",
            allowed_tlp="TLP:AMBER",
            opencti_collections="Ransomware watchlist, manufacturing sector collection",
            notes="Demo profile for private client-readiness workflow.",
        )
        scoped_task_id = app.create_portal_task(
            title="Client brief: Manufacturing Alpha ransomware VPN readiness",
            description="Prepare a private client brief for RPT-TR-2026-010 and map detections to Windows/VPN/Splunk telemetry.",
            priority=8,
            requested_by="demo",
            assignee="analyst",
            worker_profile="default",
            task_type="research",
            source_page="clients",
            research_workflow="threat-intel",
            document_category="Threat Reports",
        )
        app.update_task_client_association(scoped_task_id, client_id, actor="demo")

        # Queue a missing-upload task, then reconcile a previously queued upload
        # task from the synthetic state. In production, the latter is created
        # before the uploader completes and the state file gains opencti_id.
        upload_queue = app.queue_opencti_upload_tasks(kit_root, upload_state_path=upload_state, requested_by="demo")
        app.create_portal_task(
            title="OpenCTI upload: Manufacturing VPN Ransomware Intrusion Readiness",
            description="- Report ID: `RPT-TR-2026-010`\n- Report path: `reports/threat-reports/RPT-TR-2026-010_manufacturing-vpn-ransomware-readiness`",
            priority=6,
            requested_by="demo",
            assignee="analyst",
            worker_profile="default",
            task_type="research",
            source_page="opencti-upload",
            research_workflow="threat-intel",
            document_category="Threat Reports",
        )
        reconcile = app.reconcile_opencti_upload_results(upload_state, actor="demo")

        # Queue registry remediation and OpenCTI curation candidates.
        registry_queue = app.queue_registry_remediation_tasks(kit_root, requested_by="demo")
        curation_queue = app.import_opencti_curation_candidates(audit_dir=audit_dir, requested_by="demo")

        client_export = app.client_engagement_export(client_id, kit_root)
        client_brief = app.build_client_brief(client_id, kit_root)
        intel_summary = app.intel_ops_summary()

        print("Your Organization private intel-ops demo")
        print(f"Temporary demo root: {tmp}")
        print(f"Synthetic registry: {registry_artifact}")
        print_block("1. Client engagement export summary", client_export["summary"])
        print_block("2. Client brief", {
            "client": client_brief["client"]["org_alias"],
            "executive_summary": client_brief["executive_summary"],
            "recommended_actions": client_brief["recommended_actions"],
            "relevant_report_ids": [r.get("report_id") for r in client_brief["relevant_reports"]],
            "detection_files": [d.get("file_path") for d in client_brief["detection_handoff"]],
        })
        print_block("3. OpenCTI upload queue", upload_queue)
        print_block("4. OpenCTI upload reconciliation", reconcile)
        print_block("5. Registry remediation queue", {
            "created_count": registry_queue["created_count"],
            "skipped_existing_count": registry_queue["skipped_existing_count"],
            "duplicate_report_ids": registry_queue["duplicate_report_ids"],
            "missing_final_pdf_count": len(registry_queue["missing_final_pdf"]),
        })
        print_block("6. OpenCTI curation import", curation_queue)
        print_block("7. Intel ops dashboard rollup", {
            "opencti_upload_gaps": intel_summary["opencti"]["missing_opencti_uploads"],
            "curation_candidate_count": intel_summary["opencti"]["curation_candidate_count"],
            "registry_missing_final_pdf": intel_summary["analyst_registry"].get("missing_final_pdf"),
            "client_profiles": len(intel_summary["clients"]),
        })
        print("\nDemo completed without touching live portal/OpenCTI state.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
