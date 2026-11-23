
"""Integration regression tests against the REAL CampusShield Flask app.

These confirm the instructor blueprint is registered and works after
password authentication, privileged MFA, and the existing CSRF flow.
All accounts, grades, keys and databases here are fictional/test-only.
"""

import os

import pyotp
import pytest
from cryptography.fernet import Fernet

os.environ.setdefault(
    "CAMPUSSHIELD_SECRET_KEY",
    "test-only-secret-key-not-for-production-123456789",
)

import db
from app import app
from seed_demo import seed_database
from security.encryption import encrypt_secret
from security.passwords import hash_password

TEST_PASSWORD = "CampusShield-Test-2026!"


@pytest.fixture
def integrated_client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "phase3_integration.db")
    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    app.config.update(TESTING=True)
    seed_database()
    secret = pyotp.random_base32()

    with db.get_connection() as conn:
        for username in ("student01", "instructor01", "instructor02"):
            conn.execute(
                "UPDATE users SET password_hash = ?, is_active = 1 "
                "WHERE username = ?",
                (hash_password(TEST_PASSWORD), username),
            )
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            ("instructor01",),
        ).fetchone()
        conn.execute(
            "INSERT INTO mfa_credentials "
            "(user_id, encrypted_secret, last_used_step, is_enabled) "
            "VALUES (?, ?, -1, 1)",
            (user["id"], encrypt_secret(secret)),
        )

    with app.test_client() as client:
        yield client, secret


def _login(client, username):
    response = client.get("/login")
    assert response.status_code == 200
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    return client.post(
        "/login",
        data={
            "username": username,
            "password": TEST_PASSWORD,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )


def _authenticate_instructor(client, secret):
    password_response = _login(client, "instructor01")
    assert password_response.status_code == 302
    assert "/verify-mfa" in password_response.location

    with client.session_transaction() as sess:
        assert "user_id" not in sess
        csrf = sess["csrf_token"]

    mfa_response = client.post(
        "/verify-mfa",
        data={
            "csrf_token": csrf,
            "code": pyotp.TOTP(secret).now(),
        },
        follow_redirects=False,
    )
    assert mfa_response.status_code == 302
    with client.session_transaction() as sess:
        assert "user_id" in sess
        assert "pending_mfa_user_id" not in sess
        return sess["csrf_token"]


def _enrollment_id(username, course_code):
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT e.id FROM enrollments e "
            "JOIN users u ON u.id = e.student_id "
            "JOIN courses c ON c.id = e.course_id "
            "WHERE u.username = ? AND c.code = ?",
            (username, course_code),
        ).fetchone()
        assert row is not None
        return row["id"]


def _course_id(code):
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM courses WHERE code = ?", (code,),
        ).fetchone()
        assert row is not None
        return row["id"]


def _grade(enrollment_id):
    with db.get_connection() as conn:
        return conn.execute(
            "SELECT score FROM grades WHERE enrollment_id = ?",
            (enrollment_id,),
        ).fetchone()["score"]


def test_blueprint_registered_and_anonymous_rejected(integrated_client):
    client, _ = integrated_client
    assert client.get("/instructor/").status_code == 401


def test_mfa_is_required_before_instructor_access(integrated_client):
    client, _ = integrated_client
    _login(client, "instructor01")
    assert client.get("/instructor/").status_code == 401


def test_instructor_home_link_and_dashboard_after_real_mfa(integrated_client):
    client, secret = integrated_client
    _authenticate_instructor(client, secret)
    home = client.get("/")
    assert home.status_code == 200
    assert b"Instructor Dashboard" in home.data
    assert b"/instructor/" in home.data
    dashboard = client.get(
        f"/instructor/?course_id={_course_id('CS2413')}"
    )
    assert dashboard.status_code == 200
    assert b"student01" in dashboard.data


def test_real_mfa_instructor_can_change_only_assigned_grade(integrated_client):
    client, secret = integrated_client
    csrf = _authenticate_instructor(client, secret)
    allowed = _enrollment_id("student01", "CS2413")
    denied = _enrollment_id("student01", "CS2383")
    before = _grade(denied)

    response = client.post(
        f"/instructor/grades/{allowed}",
        data={"score": "95", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert _grade(allowed) == 95

    response = client.post(
        f"/instructor/grades/{denied}",
        data={"score": "10", "csrf_token": csrf},
    )
    assert response.status_code == 403
    assert _grade(denied) == before


def test_student_login_cannot_open_or_modify_instructor_routes(integrated_client):
    client, _ = integrated_client
    response = _login(client, "student01")
    assert response.status_code == 302
    assert client.get("/instructor/").status_code == 403
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]

    enrollment = _enrollment_id("student01", "CS2413")
    old_grade = _grade(enrollment)
    response = client.post(
        f"/instructor/grades/{enrollment}",
        data={"score": "0", "csrf_token": csrf},
    )
    assert response.status_code == 403
    assert _grade(enrollment) == old_grade


def test_real_mfa_instructor_grade_update_requires_csrf(integrated_client):
    client, secret = integrated_client
    _authenticate_instructor(client, secret)
    enrollment = _enrollment_id("student01", "CS2413")
    before = _grade(enrollment)
    response = client.post(
        f"/instructor/grades/{enrollment}",
        data={"score": "55"},
    )
    assert response.status_code == 400
    assert _grade(enrollment) == before


def test_oversized_enrollment_id_is_rejected_not_server_error(integrated_client):
    client, secret = integrated_client
    csrf = _authenticate_instructor(client, secret)
    enrollment = _enrollment_id("student01", "CS2413")
    before = _grade(enrollment)
    response = client.post(
        "/instructor/grades/999999999999999999999999999999",
        data={"score": "0", "csrf_token": csrf},
    )
    assert response.status_code == 400
    assert _grade(enrollment) == before
