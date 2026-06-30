from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import closing


VALID_RUN_STATUSES = {"queued", "running", "waiting_approval", "blocked", "failed", "completed", "cancelled"}
VALID_STEP_STATUSES = {"queued", "running", "waiting_approval", "blocked", "failed", "completed", "cancelled"}


def normalize_run_status(status: str) -> str:
    normalized = (status or "queued").strip() or "queued"
    if normalized not in VALID_RUN_STATUSES:
        raise ValueError(f"Unsupported workflow run status: {normalized}")
    return normalized


def normalize_step_status(status: str) -> str:
    normalized = (status or "queued").strip() or "queued"
    if normalized not in VALID_STEP_STATUSES:
        raise ValueError(f"Unsupported workflow step status: {normalized}")
    return normalized


def create_workflow_run(
    playbook_key: str,
    *,
    requested_by: str,
    playbook_definition_by_key: Callable[[str], dict | None],
    connect_db: Callable[[], object],
    now_utc: Callable[[], object],
    case_id: int = 0,
    trigger_type: str = "manual",
    input_data: dict | None = None,
) -> int:
    definition = playbook_definition_by_key(playbook_key)
    if not definition:
        raise ValueError(f"Unknown playbook: {playbook_key}")
    stamp = now_utc().isoformat()
    with closing(connect_db()) as connection:
        cursor = connection.execute(
            """
            INSERT INTO workflow_runs (playbook_key, status, trigger_type, requested_by, case_id, input_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                str(definition["key"]),
                "queued",
                (trigger_type or "manual").strip() or "manual",
                (requested_by or "system").strip() or "system",
                int(case_id or 0),
                json.dumps(input_data or {}, sort_keys=True),
                stamp,
                stamp,
            ],
        )
        run_id = int(cursor.lastrowid)
        for step in definition.get("steps", []):
            connection.execute(
                """
                INSERT INTO workflow_run_steps (run_id, step_id, action, status, output_data, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    run_id,
                    str(step.get("id") or ""),
                    str(step.get("action") or ""),
                    "queued",
                    json.dumps({}, sort_keys=True),
                    stamp,
                    stamp,
                ],
            )
        connection.commit()
    return run_id


def fetch_workflow_run(run_id: int, *, fetch_one: Callable[[str, list], object | None], load_json_object: Callable[[str], dict]) -> dict | None:
    row = fetch_one(
        "SELECT id, playbook_key, status, trigger_type, requested_by, case_id, input_data, created_at, updated_at FROM workflow_runs WHERE id = ?",
        [int(run_id)],
    )
    if not row:
        return None
    item = dict(row)
    item["input_data"] = load_json_object(item.get("input_data", "{}"))
    return item


def fetch_workflow_run_steps(run_id: int, *, fetch_all: Callable[[str, list], list], load_json_object: Callable[[str], dict]) -> list[dict]:
    rows = fetch_all(
        "SELECT id, run_id, step_id, action, status, output_data, created_at, updated_at FROM workflow_run_steps WHERE run_id = ? ORDER BY id ASC",
        [int(run_id)],
    )
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["output_data"] = load_json_object(item.get("output_data", "{}"))
        items.append(item)
    return items


def fetch_workflow_runs(
    *,
    limit: int,
    fetch_all: Callable[[str, list], list],
    list_cases: Callable[..., list[dict]],
    load_json_object: Callable[[str], dict],
    playbook_definition_by_key: Callable[[str], dict | None],
    fetch_workflow_run_steps_fn: Callable[[int], list[dict]],
    statuses: list[str] | tuple[str, ...] | None = None,
) -> list[dict]:
    query = "SELECT id, playbook_key, status, trigger_type, requested_by, case_id, input_data, created_at, updated_at FROM workflow_runs"
    params: list = []
    normalized_statuses = [str(status or "").strip().lower() for status in (statuses or []) if str(status or "").strip()]
    if normalized_statuses:
        placeholders = ", ".join("?" for _ in normalized_statuses)
        query += f" WHERE lower(trim(status)) IN ({placeholders})"
        params.extend(normalized_statuses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = fetch_all(query, params)
    cases_by_id = {int(case["id"]): case for case in list_cases(limit=200)}
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["input_data"] = load_json_object(item.get("input_data", "{}"))
        definition = playbook_definition_by_key(item.get("playbook_key", ""))
        item["playbook_title"] = str(definition.get("title")) if definition else str(item.get("playbook_key") or "")
        item["case_title"] = ""
        case_id = int(item.get("case_id") or 0)
        if case_id and case_id in cases_by_id:
            item["case_title"] = str(cases_by_id[case_id].get("title") or "")
        item["steps"] = fetch_workflow_run_steps_fn(int(item["id"]))
        items.append(item)
    return items


def transition_workflow_run(run_id: int, status: str, *, execute: Callable[[str, list], object], now_utc: Callable[[], object]) -> None:
    normalized_status = normalize_run_status(status)
    stamp = now_utc().isoformat()
    execute(
        "UPDATE workflow_runs SET status = ?, updated_at = ? WHERE id = ?",
        [normalized_status, stamp, int(run_id)],
    )
    if normalized_status in {"completed", "failed", "cancelled"}:
        execute(
            "UPDATE workflow_run_steps SET status = ?, updated_at = ? WHERE run_id = ? AND lower(trim(coalesce(status, ''))) NOT IN (?, 'completed')",
            [normalized_status, stamp, int(run_id), normalized_status],
        )


def transition_workflow_step(
    run_id: int,
    step_id: str,
    status: str,
    *,
    execute: Callable[[str, list], object],
    now_utc: Callable[[], object],
    output_data: dict | None = None,
) -> None:
    normalized_status = normalize_step_status(status)
    execute(
        "UPDATE workflow_run_steps SET status = ?, output_data = ?, updated_at = ? WHERE run_id = ? AND step_id = ?",
        [normalized_status, json.dumps(output_data or {}, sort_keys=True), now_utc().isoformat(), int(run_id), str(step_id or "")],
    )
