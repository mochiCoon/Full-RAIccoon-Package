from __future__ import annotations

from pathlib import Path

PLAYBOOKS_DIR = Path(__file__).resolve().parents[2] / "playbooks"
REQUIRED_FIELDS = ("key", "title", "scope", "trigger", "steps")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_scalar(value: str):
    value = _strip_quotes(value)
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.isdigit():
        return int(value)
    return value


def _parse_simple_playbook_yaml(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    data: dict = {}
    index = 0
    while index < len(lines):
        raw_line = lines[index]
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if raw_line.startswith((" ", "\t")):
            raise ValueError(f"Unexpected indentation in {path.name}: {raw_line}")
        if ":" not in raw_line:
            raise ValueError(f"Invalid playbook line in {path.name}: {raw_line}")
        key, remainder = raw_line.split(":", 1)
        key = key.strip()
        value = remainder.strip()
        if value:
            data[key] = _parse_scalar(value)
            index += 1
            continue
        if key != "steps":
            data[key] = ""
            index += 1
            continue
        steps: list[dict] = []
        index += 1
        while index < len(lines):
            step_line = lines[index]
            step_stripped = step_line.strip()
            if not step_stripped or step_stripped.startswith("#"):
                index += 1
                continue
            if not step_line.startswith("  - "):
                break
            first_item = step_line[4:]
            if ":" not in first_item:
                raise ValueError(f"Invalid step definition in {path.name}: {step_line}")
            step_key, step_value = first_item.split(":", 1)
            step = {step_key.strip(): _parse_scalar(step_value.strip())}
            index += 1
            while index < len(lines):
                nested_line = lines[index]
                nested_stripped = nested_line.strip()
                if not nested_stripped or nested_stripped.startswith("#"):
                    index += 1
                    continue
                if not nested_line.startswith("    "):
                    break
                if ":" not in nested_line:
                    raise ValueError(f"Invalid nested step field in {path.name}: {nested_line}")
                nested_key, nested_value = nested_line.strip().split(":", 1)
                step[nested_key.strip()] = _parse_scalar(nested_value.strip())
                index += 1
            steps.append(step)
        data[key] = steps
    return data


def _validate_playbook(definition: dict, *, source: Path) -> dict:
    for field in REQUIRED_FIELDS:
        if field not in definition:
            raise ValueError(f"Playbook {source.name} missing required field: {field}")
    steps = definition.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"Playbook {source.name} must define at least one step")
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError(f"Playbook {source.name} has a non-object step")
        if not step.get("id") or not step.get("action"):
            raise ValueError(f"Playbook {source.name} steps require id and action")
    normalized = dict(definition)
    normalized["description"] = str(normalized.get("description") or "")
    normalized["steps"] = [dict(step) for step in steps]
    normalized["path"] = str(source)
    return normalized


def load_playbook_definition(path: str | Path) -> dict:
    source = Path(path)
    definition = _parse_simple_playbook_yaml(source)
    return _validate_playbook(definition, source=source)


def list_playbook_definitions(root: str | Path | None = None) -> list[dict]:
    playbook_root = Path(root) if root is not None else PLAYBOOKS_DIR
    catalog = [load_playbook_definition(path) for path in sorted(playbook_root.glob("*.yaml"))]
    return sorted(catalog, key=lambda item: str(item.get("key") or ""))
