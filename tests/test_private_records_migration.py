"""Phase 4A migration tests; never use a developer's live SQLite file."""

import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db
from scripts.init_private_records import migrate_private_records


@pytest.fixture
def temp_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "private_records_test.db")
    db.init_db()
    conn = db.get_connection()
    try:
        conn.executemany(
            """INSERT INTO users
               (id, username, full_name, password_hash, role, is_active)
               VALUES (?, ?, ?, ?, ?, 1)""",
            [
                (1, "student01", "Fictional Student", "!TEST_ONLY", "student"),
                (2, "instructor01", "Fictional Instructor", "!TEST_ONLY", "instructor"),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return db.DB_PATH


@pytest.fixture
def ciphertext_pair():
    cipher = Fernet(Fernet.generate_key())
    return (
        cipher.encrypt(b"student@example.invalid").decode("ascii"),
        cipher.encrypt(b"+15065550123").decode("ascii"),
    )


def test_migration_adds_table_and_preserves_users(temp_database):
    migrate_private_records()
    conn = db.get_connection()
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'student_private_records'"
        ).fetchone() is not None
    finally:
        conn.close()


def test_migration_is_idempotent(temp_database, ciphertext_pair):
    migrate_private_records()
    conn = db.get_connection()
    try:
        conn.execute(
            """INSERT INTO student_private_records
               (student_id, encrypted_email, encrypted_phone)
               VALUES (?, ?, ?)""",
            (1, *ciphertext_pair),
        )
        conn.commit()
    finally:
        conn.close()

    migrate_private_records()
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT encrypted_email, encrypted_phone "
            "FROM student_private_records WHERE student_id = ?", (1,)
        ).fetchone()
        assert tuple(row) == ciphertext_pair
        assert conn.execute(
            "SELECT COUNT(*) FROM student_private_records"
        ).fetchone()[0] == 1
    finally:
        conn.close()


@pytest.mark.parametrize("student_id", [2, 9999])
def test_nonstudent_or_unknown_user_rejected(
    temp_database, ciphertext_pair, student_id
):
    migrate_private_records()
    conn = db.get_connection()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO student_private_records
                   (student_id, encrypted_email, encrypted_phone)
                   VALUES (?, ?, ?)""",
                (student_id, *ciphertext_pair),
            )
        conn.rollback()
    finally:
        conn.close()


@pytest.mark.parametrize("invalid_index", [0, 1])
def test_empty_ciphertext_rejected(
    temp_database, ciphertext_pair, invalid_index
):
    migrate_private_records()
    values = list(ciphertext_pair)
    values[invalid_index] = ""
    conn = db.get_connection()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO student_private_records
                   (student_id, encrypted_email, encrypted_phone)
                   VALUES (?, ?, ?)""",
                (1, *values),
            )
        conn.rollback()
    finally:
        conn.close()


def test_foreign_key_cascade(temp_database, ciphertext_pair):
    migrate_private_records()
    conn = db.get_connection()
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        conn.execute(
            """INSERT INTO student_private_records
               (student_id, encrypted_email, encrypted_phone)
               VALUES (?, ?, ?)""",
            (1, *ciphertext_pair),
        )
        conn.execute("DELETE FROM users WHERE id = ?", (1,))
        conn.commit()
        assert conn.execute(
            "SELECT COUNT(*) FROM student_private_records"
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_missing_database_fails_without_creating_one(tmp_path, monkeypatch):
    missing = tmp_path / "does_not_exist.db"
    monkeypatch.setattr(db, "DB_PATH", missing)
    with pytest.raises(FileNotFoundError):
        migrate_private_records()
    assert not missing.exists()
