"""Phase 4A: black-box regression checks against existing Flask routes.

No routes are added. Each test uses a temporary SQLite database and a
fictional test password. Injection probes are inputs, never executable SQL.
"""

import pytest

import db

TEST_PASSWORD = "CampusShield-Checkpoint4-Test!"

LOGIN_ATTACKS = [
    "student01' OR 1=1 --",
    "' OR '1'='1",
    "student01'; DROP TABLE users; --",
    "' UNION SELECT id, username, role, password_hash, is_active FROM users --",
    "%",
    "_",
]


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Configure before importing app when this file is run alone.
    monkeypatch.setenv(
        "CAMPUSSHIELD_SECRET_KEY",
        "checkpoint4-test-secret-key-only-not-for-production-2026",
    )
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "flask_sql_regression.db")

    from app import app
    from seed_demo import seed_database
    from security.passwords import hash_password

    seed_database()
    connection = db.get_connection()
    try:
        connection.execute(
            "UPDATE users SET password_hash = ?, is_active = 1 WHERE username = ?",
            (hash_password(TEST_PASSWORD), "student01"),
        )
        connection.commit()
    finally:
        connection.close()

    # Do not globally reconfigure the app's registered routes or shared modules.
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


def _login(client, username):
    client.get("/login")
    with client.session_transaction() as session:
        token = session["csrf_token"]
    return client.post(
        "/login",
        data={
            "username": username,
            "password": TEST_PASSWORD,
            "csrf_token": token,
        },
        follow_redirects=False,
    )


@pytest.mark.parametrize("attack", LOGIN_ATTACKS)
def test_sql_injection_in_username_cannot_bypass_login(client, attack):
    response = _login(client, attack)
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "pending_mfa_user_id" not in session
    conn = db.get_connection()
    try:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 6
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        # The value was stored as a *username string* in the throttling table.
        row = conn.execute(
            "SELECT failure_count FROM auth_attempts WHERE username = ? AND stage = ?",
            (attack.strip().lower(), "password"),
        ).fetchone()
        assert row is not None and row["failure_count"] == 1
    finally:
        conn.close()


def test_record_search_parameters_do_not_override_authenticated_student(client):
    response = _login(client, "student01")
    assert response.status_code == 302
    assert "/records" in response.location

    response = client.get(
        "/records?student_id=2&username=student02&"
        "search=%27%20OR%201%3D1%20--&role=security_admin"
    )
    assert response.status_code == 200
    assert b"94%" in response.data
    assert b"88%" in response.data
    assert b"73%" not in response.data
    assert b"86%" not in response.data


def test_record_search_parameters_without_login_do_not_allow_access(client):
    response = client.get("/records?student_id=1&user_id=1&role=student")
    assert response.status_code == 302
    assert "/login" in response.location


def test_login_role_and_user_id_form_fields_cannot_force_privileged_session(client):
    client.get("/login")
    with client.session_transaction() as session:
        token = session["csrf_token"]
    response = client.post(
        "/login",
        data={
            "username": "student01",
            "password": TEST_PASSWORD,
            "csrf_token": token,
            "role": "security_admin",
            "user_id": "9999",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/records" in response.location
    with client.session_transaction() as session:
        assert type(session["user_id"]) is int
    conn = db.get_connection()
    try:
        stored = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("student01",)
        ).fetchone()
        with client.session_transaction() as session:
            assert session["user_id"] == stored["id"]
    finally:
        conn.close()
