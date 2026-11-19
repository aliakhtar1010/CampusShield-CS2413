
import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1])
)

os.environ.setdefault(
    "CAMPUSSHIELD_SECRET_KEY",
    "test-only-secret-key-not-for-production-123456789"
)

import db

from app import app
from seed_demo import seed_database
from security.passwords import hash_password
from security.encryption import encrypt_secret
from security.throttle import get_auth_status
from security.mfa import generate_mfa_secret


TEST_PASSWORD = "CampusShield-Test-2026!"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        db,
        "DB_PATH",
        tmp_path / "throttle_integration.db"
    )

    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY",
        Fernet.generate_key().decode()
    )

    app.config.update(TESTING=True)
    seed_database()

    conn = db.get_connection()

    try:
        for username in ("student01", "instructor01"):
            conn.execute("""
                UPDATE users
                SET password_hash = ?, is_active = 1
                WHERE username = ?
            """, (
                hash_password(TEST_PASSWORD),
                username
            ))

        instructor = conn.execute("""
            SELECT id FROM users
            WHERE username = ?
        """, ("instructor01",)).fetchone()

        conn.execute("""
            INSERT INTO mfa_credentials (
                user_id,
                encrypted_secret,
                last_used_step,
                is_enabled
            )
            VALUES (?, ?, -1, 1)
        """, (
            instructor["id"],
            encrypt_secret(generate_mfa_secret())
        ))

        conn.commit()

    finally:
        conn.close()

    with app.test_client() as test_client:
        yield test_client


def login(client, username, password):
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


def submit_mfa(client, code):
    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    return client.post(
        "/verify-mfa",
        data={
            "code": code,
            "csrf_token": token
        },
        follow_redirects=False
    )


def test_five_password_failures_lock_account(client):
    for _ in range(5):
        login(
            client,
            "student01",
            "IncorrectPassword2026!"
        )

    status = get_auth_status(
        "student01", "password"
    )

    assert status["blocked"] is True

    response = login(
        client,
        "student01",
        TEST_PASSWORD
    )

    assert response.status_code == 200
    assert b"Too many authentication attempts" in response.data

    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_password_lockout_survives_new_session(client):
    for _ in range(5):
        login(
            client,
            "student01",
            "IncorrectPassword2026!"
        )

    # A fresh Flask client has new cookies, but
    # shares the same server-side SQLite database.
    with app.test_client() as new_client:
        response = login(
            new_client,
            "student01",
            TEST_PASSWORD
        )

        assert response.status_code == 200
        assert b"Too many authentication attempts" in response.data


def test_successful_password_resets_failure_count(client):
    for _ in range(3):
        login(
            client,
            "student01",
            "IncorrectPassword2026!"
        )

    before = get_auth_status(
        "student01", "password"
    )

    assert before["failures"] == 3

    response = login(
        client,
        "student01",
        TEST_PASSWORD
    )

    assert response.status_code == 302

    after = get_auth_status(
        "student01", "password"
    )

    assert after["failures"] == 0


def test_mfa_failures_trigger_persistent_lockout(client):
    response = login(
        client,
        "instructor01",
        TEST_PASSWORD
    )

    assert response.status_code == 302
    assert "/verify-mfa" in response.location

    for _ in range(5):
        response = submit_mfa(
            client,
            "invalid"
        )

    assert response.status_code == 302

    status = get_auth_status(
        "instructor01", "mfa"
    )

    assert status["blocked"] is True

    # Even after a fresh password authentication,
    # a new MFA challenge must not be issued.
    client.get("/login")

    response = login(
        client,
        "instructor01",
        TEST_PASSWORD
    )

    assert response.status_code == 200
    assert b"Too many authentication attempts" in response.data

    with client.session_transaction() as sess:
        assert "user_id" not in sess
        assert "pending_mfa_user_id" not in sess


def test_password_and_mfa_counters_are_separate(client):
    for _ in range(2):
        login(
            client,
            "instructor01",
            "IncorrectPassword2026!"
        )

    password_status = get_auth_status(
        "instructor01", "password"
    )

    mfa_status = get_auth_status(
        "instructor01", "mfa"
    )

    assert password_status["failures"] == 2
    assert mfa_status["failures"] == 0
