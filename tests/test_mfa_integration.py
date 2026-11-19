
import os
import sys
import time
from pathlib import Path

import pyotp
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


TEST_PASSWORD = "CampusShield-Test-2026!"


@pytest.fixture
def mfa_client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        db,
        "DB_PATH",
        tmp_path / "mfa_test.db"
    )

    key = Fernet.generate_key().decode()

    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY",
        key
    )

    app.config.update(TESTING=True)
    seed_database()

    secret = pyotp.random_base32()

    conn = db.get_connection()

    try:
        conn.execute("""
            UPDATE users
            SET password_hash = ?, is_active = 1
            WHERE username = 'instructor01'
        """, (hash_password(TEST_PASSWORD),))

        instructor = conn.execute("""
            SELECT id FROM users
            WHERE username = 'instructor01'
        """).fetchone()

        conn.execute("""
            INSERT INTO mfa_credentials (
                user_id, encrypted_secret,
                last_used_step, is_enabled
            )
            VALUES (?, ?, -1, 1)
        """, (
            instructor["id"],
            encrypt_secret(secret)
        ))

        conn.commit()

    finally:
        conn.close()

    with app.test_client() as client:
        yield client, secret


def password_login(client):
    client.get("/login")

    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    return client.post(
        "/login",
        data={
            "username": "instructor01",
            "password": TEST_PASSWORD,
            "csrf_token": token
        }
    )


def submit_mfa(client, code):
    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    return client.post(
        "/verify-mfa",
        data={
            "csrf_token": token,
            "code": code
        }
    )


def test_password_requires_mfa(mfa_client):
    client, secret = mfa_client

    response = password_login(client)

    assert response.status_code == 302
    assert "/verify-mfa" in response.location


def test_pending_mfa_cannot_access_records(mfa_client):
    client, secret = mfa_client

    password_login(client)

    with client.session_transaction() as sess:
        assert "user_id" not in sess
        assert "pending_mfa_user_id" in sess

    response = client.get("/records")

    assert response.status_code == 302


def test_correct_mfa_completes_login(mfa_client):
    client, secret = mfa_client

    password_login(client)

    code = pyotp.TOTP(secret).now()

    response = submit_mfa(client, code)

    assert response.status_code == 302
    assert response.location.endswith("/")

    with client.session_transaction() as sess:
        assert "user_id" in sess
        assert "pending_mfa_user_id" not in sess


def test_invalid_mfa_rejected(mfa_client):
    client, secret = mfa_client

    password_login(client)

    response = submit_mfa(client, "abcdef")

    assert response.status_code == 200
    assert b"Invalid or previously used" in response.data

    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_mfa_code_replay_rejected(mfa_client):
    client, secret = mfa_client

    password_login(client)

    code = pyotp.TOTP(secret).now()

    first = submit_mfa(client, code)

    assert first.status_code == 302

    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    client.post(
        "/logout",
        data={"csrf_token": token}
    )

    password_login(client)

    second = submit_mfa(client, code)

    assert second.status_code == 200

    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_expired_mfa_challenge_rejected(mfa_client):
    client, secret = mfa_client

    password_login(client)

    with client.session_transaction() as sess:
        sess["pending_mfa_started"] = int(
            time.time()
        ) - 600

    response = client.get("/verify-mfa")

    assert response.status_code == 302
    assert "/login" in response.location


def test_five_failed_codes_cancel_challenge(mfa_client):
    client, secret = mfa_client

    password_login(client)

    for _ in range(5):
        response = submit_mfa(client, "invalid")

    assert response.status_code == 302
    assert "/login" in response.location

    with client.session_transaction() as sess:
        assert "pending_mfa_user_id" not in sess
        assert "user_id" not in sess


def test_instructor_cannot_view_student_records(mfa_client):
    client, secret = mfa_client

    password_login(client)

    code = pyotp.TOTP(secret).now()
    submit_mfa(client, code)

    response = client.get("/records")

    assert response.status_code == 403
