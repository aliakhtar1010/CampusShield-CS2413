"""Phase 4A: security regression evidence for database and auth queries.

All SQL injection strings are harmless inputs to a temporary test database.
No vulnerable route is created and no developer database is modified.
"""

import sqlite3

import pytest
from cryptography.fernet import Fernet

import db
from db_security.private_records import (
    PrivateRecordAccessDenied,
    get_private_record,
    save_private_record,
)
from scripts.init_private_records import migrate_private_records
from security.throttle import get_auth_status, record_auth_failure, reset_auth_failures


# Intentionally hostile strings are passed as VALUES, never SQL fragments.
INJECTION_STRINGS = [
    "' OR 1=1 --",
    "1 OR 1=1",
    "1 UNION SELECT id FROM users",
    "1; DROP TABLE users; --",
    "' UNION SELECT 1,2,3 --",
    "1/**/OR/**/1=1",
]


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "sql_injection_regression.db")
    monkeypatch.setenv("CAMPUSSHIELD_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    db.init_db()
    migrate_private_records()
    connection = db.get_connection()
    connection.executemany(
        """INSERT INTO users (id, username, full_name, password_hash, role, is_active)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            (1, "student01", "Fictional Student One", "!TEST", "student", 1),
            (2, "student02", "Fictional Student Two", "!TEST", "student", 1),
            (3, "instructor01", "Fictional Instructor", "!TEST", "instructor", 1),
            (4, "inactive01", "Fictional Inactive", "!TEST", "student", 0),
        ],
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def _save(conn, actor=1, target=1, email="student01@example.invalid"):
    save_private_record(
        conn,
        authenticated_user_id=actor,
        student_id=target,
        email=email,
        phone="+15065550123",
    )


def _assert_schema_intact(conn):
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 4
    assert conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?",
        ("table", "student_private_records"),
    ).fetchone()[0] == 1
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


@pytest.mark.parametrize("attack", INJECTION_STRINGS)
def test_injected_student_identifier_cannot_read_other_records(conn, attack):
    _save(conn)
    conn.commit()
    with pytest.raises(ValueError):
        get_private_record(conn, authenticated_user_id=1, student_id=attack)
    with pytest.raises(ValueError):
        get_private_record(conn, authenticated_user_id=attack, student_id=1)
    assert get_private_record(conn, authenticated_user_id=1, student_id=1)[
        "email"
    ] == "student01@example.invalid"
    _assert_schema_intact(conn)


@pytest.mark.parametrize("attack", INJECTION_STRINGS)
def test_injected_student_identifier_cannot_modify_record(conn, attack):
    _save(conn)
    conn.commit()
    original = tuple(conn.execute(
        "SELECT encrypted_email, encrypted_phone FROM student_private_records WHERE student_id = ?",
        (1,),
    ).fetchone())
    with pytest.raises(ValueError):
        _save(conn, target=attack, email="attacker@example.invalid")
    with pytest.raises(ValueError):
        _save(conn, actor=attack, email="attacker@example.invalid")
    assert tuple(conn.execute(
        "SELECT encrypted_email, encrypted_phone FROM student_private_records WHERE student_id = ?",
        (1,),
    ).fetchone()) == original
    _assert_schema_intact(conn)


@pytest.mark.parametrize("attack", INJECTION_STRINGS)
def test_auth_throttle_username_payload_is_stored_as_literal_data(conn, attack):
    """The real authentication throttling module uses parameterized SQL."""
    status = record_auth_failure(attack, "password")
    assert status["failures"] == 1
    normalized = attack.strip().lower()
    row = conn.execute(
        "SELECT username, failure_count FROM auth_attempts WHERE username = ? AND stage = ?",
        (normalized, "password"),
    ).fetchone()
    assert tuple(row) == (normalized, 1)
    assert get_auth_status("student01", "password")["failures"] == 0
    _assert_schema_intact(conn)


def test_injected_username_cannot_reset_legitimate_accounts_throttle(conn):
    record_auth_failure("student01", "password")
    record_auth_failure("student01' OR 1=1 --", "password")
    reset_auth_failures("student01' OR 1=1 --", "password")
    assert get_auth_status("student01", "password")["failures"] == 1
    assert get_auth_status("student01' OR 1=1 --", "password")["failures"] == 0
    _assert_schema_intact(conn)


def test_valid_student_cannot_use_auth_identifier_to_read_other_student(conn):
    _save(conn)
    conn.commit()
    with pytest.raises(PrivateRecordAccessDenied):
        get_private_record(conn, authenticated_user_id=2, student_id=1)
    _assert_schema_intact(conn)


def test_wrong_role_and_inactive_account_rejected_on_same_id(conn):
    for account in (3, 4):
        with pytest.raises(PrivateRecordAccessDenied):
            _save(conn, actor=account, target=account)
        with pytest.raises(PrivateRecordAccessDenied):
            get_private_record(conn, authenticated_user_id=account, student_id=account)
    _assert_schema_intact(conn)


def test_malformed_ciphertext_preserves_schema_but_fails_decryption(conn):
    """Database constraints cannot authenticate Fernet tokens; service does."""
    from db_security.field_encryption import PrivateFieldDecryptionError
    _save(conn)
    conn.commit()
    conn.execute(
        "UPDATE student_private_records SET encrypted_email = ? WHERE student_id = ?",
        ("A" * 200, 1),
    )
    conn.commit()
    with pytest.raises(PrivateFieldDecryptionError):
        get_private_record(conn, authenticated_user_id=1, student_id=1)
    _assert_schema_intact(conn)


def test_foreign_key_and_uniqueness_still_enforced(conn):
    _save(conn)
    conn.commit()
    row = conn.execute(
        "SELECT encrypted_email, encrypted_phone FROM student_private_records WHERE student_id = ?",
        (1,),
    ).fetchone()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO student_private_records (student_id, encrypted_email, encrypted_phone) VALUES (?, ?, ?)",
            (1, row[0], row[1]),
        )
    conn.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO student_private_records (student_id, encrypted_email, encrypted_phone) VALUES (?, ?, ?)",
            (999, row[0], row[1]),
        )
    conn.rollback()
    _assert_schema_intact(conn)
