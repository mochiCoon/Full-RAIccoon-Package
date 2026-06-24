import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "portal.db"


def columns(table: str) -> set[str]:
    with sqlite3.connect(DB_PATH) as conn:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


user_columns = columns("users")
required = {
    "mfa_recovery_codes",
    "mfa_recovery_generated_at",
    "mfa_required",
    "login_fail_count",
    "login_locked_until",
    "mfa_fail_count",
    "mfa_locked_until",
}
missing = sorted(required - user_columns)
assert not missing, f"missing required user security columns: {missing}"
print("security schema checks passed")
