"""Real Flask authentication and encrypted private-contact integration tests.

Each test uses an isolated temporary SQLite database and disposable Fernet key.
"""

import os

import pytest
from cryptography.fernet import Fernet

os.environ.setdefault(
    "CAMPUSSHIELD_SECRET_KEY", "test-only-secret-key-not-for-production-123456789"
)

import db
from app import app
from scripts.init_private_records import migrate_private_records
from seed_demo import seed_database
from security.passwords import hash_password


TEST_PASSWORD = "CampusShield-Phase4A-Test!"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "phase4a_integration.db")
    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii")
    )
    app.config.update(TESTING=True)
    seed_database()
    migrate_private_records()

    with db.get_connection() as conn:
        for username in ("student01", "student02", "instructor01"):
            conn.execute(
                "UPDATE users SET password_hash = ?, is_active = 1 "
                "WHERE username = ?",
                (hash_password(TEST_PASSWORD), username),
            )

    with app.test_client() as test_client:
        yield test_client


def _uid(username):
    with db.get_connection() as conn:
        return conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()["id"]


def _csrf(client):
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def _student_login(client, username="student01"):
    assert client.get("/login").status_code == 200
    response = client.post(
        "/login",
        data={
            "username": username,
            "password": TEST_PASSWORD,
            "csrf_token": _csrf(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/records" in response.location


def _post_contact(client, *, email="student01@example.invalid", phone="+15065550123", csrf=None, **extra):
    data = {
        "email": email,
        "phone": phone,
        "csrf_token": _csrf(client) if csrf is None else csrf,
    }
    data.update(extra)
    return client.post("/private-records/", data=data, follow_redirects=False)


def _raw(student_id):
    with db.get_connection() as conn:
        return conn.execute(
            "SELECT encrypted_email, encrypted_phone "
            "FROM student_private_records WHERE student_id = ?",
            (student_id,),
        ).fetchone()


def test_private_contact_requires_completed_login(client):
    assert client.get("/private-records/").status_code == 401
    assert client.post("/private-records/", data={}).status_code == 401


def test_pending_mfa_is_not_authentication(client):
    with client.session_transaction() as sess:
        sess["pending_mfa_user_id"] = _uid("instructor01")
        sess["csrf_token"] = "fake-test-token"
    assert client.get("/private-records/").status_code == 401


def test_student_can_open_private_contact_form(client):
    _student_login(client)
    assert b"My Private Contact" in client.get("/records").data
    response = client.get("/private-records/")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert b"Save encrypted contact" in response.data


def test_real_student_can_save_and_read_encrypted_contact(client):
    _student_login(client)
    response = _post_contact(client)
    assert response.status_code == 302
    assert "/private-records/" in response.location
    row = _raw(_uid("student01"))
    assert row is not None
    assert "student01@example.invalid" not in row["encrypted_email"]
    assert "+15065550123" not in row["encrypted_phone"]
    response = client.get(response.location)
    assert response.status_code == 200
    assert b"student01@example.invalid" in response.data
    assert b"+15065550123" in response.data
    assert b"saved securely" in response.data


def test_updating_contact_changes_ciphertext(client):
    _student_login(client)
    assert _post_contact(client).status_code == 302
    before = tuple(_raw(_uid("student01")))
    assert _post_contact(
        client, email="updated@example.invalid", phone="+15065550124"
    ).status_code == 302
    after = tuple(_raw(_uid("student01")))
    assert before != after
    assert b"updated@example.invalid" in client.get("/private-records/").data


def test_student_cannot_choose_target_user_with_form_parameter(client):
    _student_login(client)
    response = _post_contact(
        client,
        student_id=str(_uid("student02")),
        authenticated_user_id=str(_uid("student02")),
        role="security_admin",
    )
    assert response.status_code == 302
    assert _raw(_uid("student02")) is None
    assert _raw(_uid("student01")) is not None


def test_other_student_cannot_view_saved_contact(client):
    _student_login(client)
    assert _post_contact(client).status_code == 302
    with client.session_transaction() as sess:
        sess.clear()
    _student_login(client, "student02")
    response = client.get("/private-records/?student_id=1")
    assert response.status_code == 200
    assert b"student01@example.invalid" not in response.data
    assert _raw(_uid("student02")) is None


def test_instructor_cannot_open_or_save_private_contact(client):
    with client.session_transaction() as sess:
        sess["user_id"] = _uid("instructor01")
        sess["csrf_token"] = "test-token"
    assert client.get("/private-records/").status_code == 403
    assert _post_contact(client, csrf="test-token").status_code == 403


def test_missing_csrf_rejected_without_writing(client):
    _student_login(client)
    response = client.post(
        "/private-records/",
        data={"email": "student01@example.invalid", "phone": "+15065550123"},
    )
    assert response.status_code == 400
    assert _raw(_uid("student01")) is None


def test_bad_csrf_rejected_without_writing(client):
    _student_login(client)
    assert _post_contact(client, csrf="forged-token").status_code == 400
    assert _raw(_uid("student01")) is None


@pytest.mark.parametrize(
    ("email", "phone"),
    [
        ("not-an-email", "+15065550123"),
        ("student01@example.invalid", "555-0123"),
        ("x' OR 1=1 --", "+15065550123"),
    ],
)
def test_invalid_fields_rejected_without_writing(client, email, phone):
    _student_login(client)
    response = _post_contact(client, email=email, phone=phone)
    assert response.status_code == 400
    assert _raw(_uid("student01")) is None


def test_missing_encryption_key_fails_closed(client, monkeypatch):
    _student_login(client)
    assert _post_contact(client).status_code == 302
    monkeypatch.delenv("CAMPUSSHIELD_ENCRYPTION_KEY")
    response = client.get("/private-records/")
    assert response.status_code == 503
    assert b"student01@example.invalid" not in response.data


def test_tampered_ciphertext_fails_closed(client):
    _student_login(client)
    assert _post_contact(client).status_code == 302
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE student_private_records SET encrypted_email=? WHERE student_id=?",
            ("malformed-not-a-real-token", _uid("student01")),
        )
    response = client.get("/private-records/")
    assert response.status_code == 503
    assert b"student01@example.invalid" not in response.data


def test_missing_migration_returns_service_unavailable(client):
    _student_login(client)
    with db.get_connection() as conn:
        conn.execute("DROP TABLE student_private_records")
    assert client.get("/private-records/").status_code == 503


def test_deactivated_user_cannot_read_private_contact(client):
    _student_login(client)
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE users SET is_active=0 WHERE username=?", ("student01",)
        )
    assert client.get("/private-records/").status_code == 403
