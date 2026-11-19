
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1])
)

# Configure the test key before importing the Flask app.
os.environ.setdefault(
    "CAMPUSSHIELD_SECRET_KEY",
    "test-only-secret-key-not-for-production-123456789"
)

import db
from app import app
from seed_demo import seed_database
from security.passwords import hash_password


TEST_PASSWORD = "CampusShield-Test-2026!"


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Each test gets an isolated SQLite database.
    monkeypatch.setattr(
        db,
        "DB_PATH",
        tmp_path / "campusshield_test.db"
    )

    app.config.update(TESTING=True)

    seed_database()

    conn = db.get_connection()

    try:
        for username in ("student01", "student02"):
            conn.execute("""
                UPDATE users
                SET password_hash = ?, is_active = 1
                WHERE username = ?
            """, (
                hash_password(TEST_PASSWORD),
                username
            ))

        conn.commit()
    finally:
        conn.close()

    with app.test_client() as test_client:
        yield test_client


def login(client, username, password=TEST_PASSWORD):
    # Retrieve a valid CSRF token from the session.
    client.get("/login")

    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": token
        },
        follow_redirects=False
    )


def test_unauthenticated_access_blocked(client):
    response = client.get("/records")

    assert response.status_code == 302
    assert "/login" in response.location


def test_valid_login(client):
    response = login(client, "student01")

    assert response.status_code == 302
    assert "/records" in response.location

    with client.session_transaction() as sess:
        assert "user_id" in sess


def test_invalid_password_rejected(client):
    response = login(
        client,
        "student01",
        "IncorrectPassword2026!"
    )

    assert response.status_code == 200
    assert b"Invalid username or password" in response.data

    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_inactive_account_rejected(client):
    response = login(client, "student03")

    assert response.status_code == 200

    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_student_record_isolation(client):
    login(client, "student01")

    response = client.get("/records")

    assert response.status_code == 200
    assert b"94%" in response.data
    assert b"88%" in response.data

    # These grades belong to Student02.
    assert b"73%" not in response.data
    assert b"86%" not in response.data


def test_logout_removes_access(client):
    login(client, "student01")

    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    response = client.post(
        "/logout",
        data={"csrf_token": token}
    )

    assert response.status_code == 302

    protected_response = client.get("/records")

    assert protected_response.status_code == 302
    assert "/login" in protected_response.location


def test_login_csrf_protection(client):
    response = client.post(
        "/login",
        data={
            "username": "student01",
            "password": TEST_PASSWORD
        }
    )

    assert response.status_code == 400
