
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import db

MIGRATION_PATH = ROOT / "migrations" / "naoshin_private_records.sql"


def migrate_private_records() -> None:
    if not db.DB_PATH.is_file():
        raise FileNotFoundError(
            "CampusShield database does not exist; initialize it first."
        )

    conn = db.get_connection()
    try:
        users_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()
        if users_table is None:
            raise RuntimeError("CampusShield users table is missing.")

        conn.executescript(MIGRATION_PATH.read_text(encoding="utf-8"))

        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(student_private_records)")
        }
        required = {
            "student_id", "encrypted_email", "encrypted_phone",
            "created_at", "updated_at"
        }
        if not required.issubset(columns):
            raise RuntimeError(
                "Existing private-records table has an unexpected schema."
            )
    finally:
        conn.close()


if __name__ == "__main__":
    migrate_private_records()
    print("Private-records migration applied; existing data preserved.")
