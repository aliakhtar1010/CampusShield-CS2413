"""Secure data-access tests: temporary SQLite databases and temporary keys."""

import pytest
from cryptography.fernet import Fernet

import db
from db_security.field_encryption import (
    PrivateFieldConfigurationError,
    PrivateFieldDecryptionError,
)
from db_security.private_records import (
    PrivateRecordAccessDenied,
    PrivateRecordNotFound,
    get_private_record,
    save_private_record,
)
from scripts.init_private_records import migrate_private_records


@pytest.fixture
def conn(tmp_path, monkeypatch):
    """Neither fixtures nor tests touch the developer's campusshield.db."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "checkpoint3.db")
    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii")
    )
    db.init_db()
    migrate_private_records()
    connection = db.get_connection()
    connection.executemany(
        """INSERT INTO users
           (id, username, full_name, password_hash, role, is_active)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            (1, "student01", "Fictional One", "!TEST_ONLY", "student", 1),
            (2, "student02", "Fictional Two", "!TEST_ONLY", "student", 1),
            (3, "instructor01", "Fictional Instructor", "!TEST_ONLY", "instructor", 1),
            (4, "security01", "Fictional Admin", "!TEST_ONLY", "security_admin", 1),
            (5, "inactive01", "Fictional Inactive", "!TEST_ONLY", "student", 0),
        ],
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def _save(conn, user_id=1, student_id=1, email="student01@example.invalid", phone="+15065550123"):
    save_private_record(
        conn,
        authenticated_user_id=user_id,
        student_id=student_id,
        email=email,
        phone=phone,
    )


def _raw_record(conn, student_id=1):
    return conn.execute(
        "SELECT encrypted_email, encrypted_phone FROM student_private_records WHERE student_id = ?",
        (student_id,),
    ).fetchone()


def test_create_and_read_own_record(conn):
    _save(conn)
    conn.commit()
    assert get_private_record(conn, authenticated_user_id=1, student_id=1) == {
        "email": "student01@example.invalid",
        "phone": "+15065550123",
    }
    row = _raw_record(conn)
    assert row is not None
    assert "student01@example.invalid" not in row["encrypted_email"]
    assert "+15065550123" not in row["encrypted_phone"]
    assert row["encrypted_email"] != "student01@example.invalid"
    assert row["encrypted_phone"] != "+15065550123"


def test_upsert_updates_and_preserves_single_row(conn):
    _save(conn)
    before = _raw_record(conn)
    _save(conn, email="new@example.invalid", phone="+15065550124")
    conn.commit()
    after = _raw_record(conn)
    assert after["encrypted_email"] != before["encrypted_email"]
    assert after["encrypted_phone"] != before["encrypted_phone"]
    assert get_private_record(conn, authenticated_user_id=1, student_id=1) == {
        "email": "new@example.invalid",
        "phone": "+15065550124",
    }
    assert conn.execute(
        "SELECT COUNT(*) FROM student_private_records WHERE student_id = ?", (1,)
    ).fetchone()[0] == 1


def test_record_visible_to_new_connection_after_commit(conn):
    _save(conn)
    conn.commit()
    separate = db.get_connection()
    try:
        assert get_private_record(separate, authenticated_user_id=1, student_id=1)[
            "email"
        ] == "student01@example.invalid"
    finally:
        separate.close()


def test_missing_record_is_not_found_for_active_student(conn):
    with pytest.raises(PrivateRecordNotFound):
        get_private_record(conn, authenticated_user_id=2, student_id=2)


@pytest.mark.parametrize("actor,target", [(1, 2), (2, 1), (3, 1), (4, 1)])
def test_cross_account_read_is_denied(conn, actor, target):
    _save(conn)
    conn.commit()
    with pytest.raises(PrivateRecordAccessDenied):
        get_private_record(conn, authenticated_user_id=actor, student_id=target)


@pytest.mark.parametrize("actor,target", [(1, 2), (2, 1), (3, 1), (4, 1)])
def test_cross_account_write_is_denied(conn, actor, target):
    _save(conn)
    conn.commit()
    before = tuple(_raw_record(conn))
    with pytest.raises(PrivateRecordAccessDenied):
        _save(conn, user_id=actor, student_id=target, email="attacker@example.invalid")
    assert tuple(_raw_record(conn)) == before


@pytest.mark.parametrize("actor", [3, 4, 5, 9999])
def test_nonstudent_inactive_or_unknown_actor_cannot_save(conn, actor):
    with pytest.raises(PrivateRecordAccessDenied):
        _save(conn, user_id=actor, student_id=actor)
    assert conn.execute("SELECT COUNT(*) FROM student_private_records").fetchone()[0] == 0


@pytest.mark.parametrize("actor", [3, 4, 5, 9999])
def test_nonstudent_inactive_or_unknown_actor_cannot_read(conn, actor):
    with pytest.raises(PrivateRecordAccessDenied):
        get_private_record(conn, authenticated_user_id=actor, student_id=actor)


def test_deactivation_blocks_read_and_update(conn):
    _save(conn)
    conn.commit()
    original = tuple(_raw_record(conn))
    conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (1,))
    conn.commit()
    with pytest.raises(PrivateRecordAccessDenied):
        get_private_record(conn, authenticated_user_id=1, student_id=1)
    with pytest.raises(PrivateRecordAccessDenied):
        _save(conn, email="new@example.invalid")
    assert tuple(_raw_record(conn)) == original


def test_role_change_blocks_read_and_update(conn):
    _save(conn)
    conn.commit()
    conn.execute("UPDATE users SET role = 'instructor' WHERE id = ?", (1,))
    conn.commit()
    with pytest.raises(PrivateRecordAccessDenied):
        get_private_record(conn, authenticated_user_id=1, student_id=1)
    with pytest.raises(PrivateRecordAccessDenied):
        _save(conn)


@pytest.mark.parametrize("invalid", [None, 0, -1, True, 1.0, "1 OR 1=1", "1; DROP TABLE users;--"])
def test_malicious_or_invalid_actor_id_is_rejected(conn, invalid):
    with pytest.raises(ValueError):
        get_private_record(conn, authenticated_user_id=invalid, student_id=1)
    with pytest.raises(ValueError):
        _save(conn, user_id=invalid)


@pytest.mark.parametrize("invalid", [None, 0, -1, False, 1.0, "1 OR 1=1", "1; DROP TABLE users;--"])
def test_malicious_or_invalid_target_id_is_rejected(conn, invalid):
    with pytest.raises(ValueError):
        get_private_record(conn, authenticated_user_id=1, student_id=invalid)
    with pytest.raises(ValueError):
        _save(conn, student_id=invalid)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 5


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("email", "injected@example.invalid' OR 1=1 --"),
        ("phone", "+1506' OR 1=1 --"),
        ("email", ""),
        ("phone", "+00000000"),
    ],
)
def test_invalid_input_never_writes_partial_record(conn, field, bad_value):
    kwargs = {field: bad_value}
    with pytest.raises(ValueError):
        save_private_record(
            conn,
            authenticated_user_id=1,
            student_id=1,
            email=kwargs.get("email", "student01@example.invalid"),
            phone=kwargs.get("phone", "+15065550123"),
        )
    assert _raw_record(conn) is None


def test_invalid_update_does_not_replace_old_ciphertext(conn):
    _save(conn)
    conn.commit()
    old = tuple(_raw_record(conn))
    with pytest.raises(ValueError):
        _save(conn, email="not an email")
    assert tuple(_raw_record(conn)) == old


@pytest.mark.parametrize("column", ["encrypted_email", "encrypted_phone"])
def test_tampered_database_token_is_rejected(conn, column):
    _save(conn)
    conn.commit()
    # Only tests perform direct SQL tampering. The service never exposes this.
    # Column selection is a fixed whitelist in tests; no SQL interpolation.
    if column == "encrypted_email":
        conn.execute(
            "UPDATE student_private_records SET encrypted_email = ? WHERE student_id = ?",
            ("tampered-not-a-valid-token", 1),
        )
    else:
        conn.execute(
            "UPDATE student_private_records SET encrypted_phone = ? WHERE student_id = ?",
            ("tampered-not-a-valid-token", 1),
        )
    conn.commit()
    with pytest.raises(PrivateFieldDecryptionError):
        get_private_record(conn, authenticated_user_id=1, student_id=1)


def test_valid_ciphertext_moved_to_another_student_is_rejected(conn):
    _save(conn)
    _save(conn, user_id=2, student_id=2, email="student02@example.invalid", phone="+15065550125")
    conn.commit()
    stolen = _raw_record(conn, 2)["encrypted_email"]
    conn.execute(
        "UPDATE student_private_records SET encrypted_email = ? WHERE student_id = ?",
        (stolen, 1),
    )
    conn.commit()
    with pytest.raises(PrivateFieldDecryptionError):
        get_private_record(conn, authenticated_user_id=1, student_id=1)


def test_missing_key_fails_closed_on_read_and_write(conn, monkeypatch):
    _save(conn)
    conn.commit()
    monkeypatch.delenv("CAMPUSSHIELD_ENCRYPTION_KEY")
    with pytest.raises(PrivateFieldConfigurationError):
        get_private_record(conn, authenticated_user_id=1, student_id=1)
    with pytest.raises(PrivateFieldConfigurationError):
        _save(conn, email="new@example.invalid")


def test_wrong_key_fails_decryption(conn, monkeypatch):
    _save(conn)
    conn.commit()
    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii")
    )
    with pytest.raises(PrivateFieldDecryptionError):
        get_private_record(conn, authenticated_user_id=1, student_id=1)


def test_no_decryption_on_denied_request(conn, monkeypatch):
    _save(conn)
    conn.commit()
    import db_security.private_records as private_records

    def unexpected_decryption(*args, **kwargs):
        raise AssertionError("Decryption must follow authorization")

    monkeypatch.setattr(private_records, "decrypt_field", unexpected_decryption)
    with pytest.raises(PrivateRecordAccessDenied):
        get_private_record(conn, authenticated_user_id=2, student_id=1)


def test_parameterized_query_does_not_modify_schema(conn):
    _save(conn)
    conn.commit()
    with pytest.raises(ValueError):
        get_private_record(
            conn,
            authenticated_user_id=1,
            student_id="1; DROP TABLE student_private_records; --",
        )
    assert conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("student_private_records",),
    ).fetchone() is not None
