
"""Integration tests for Rehan's instructor Flask blueprint.

Uses an isolated SQLite database and a standalone Flask test app.
Does not modify or register routes in Ali's app.py.
"""

import secrets
import sys
from pathlib import Path

import pytest
from flask import Flask, session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db
from seed_demo import seed_database
from routes.instructor import instructor_bp


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        db, "DB_PATH", tmp_path / "instructor_routes_test.db"
    )

    seed_database()

    conn = db.get_connection()
    try:
        conn.execute("UPDATE users SET is_active = 1")
        conn.commit()
    finally:
        conn.close()

    app = Flask(
        __name__,
        template_folder=str(
            Path(__file__).resolve().parents[1] / "templates"
        ),
    )
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-instructor-session-key",
    )

    # Match Ali's existing csrf_token() template interface.
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.register_blueprint(instructor_bp)

    with app.test_client() as test_client:
        yield test_client


def lookup_id(table, column, value):
    allowed = {
        ("users", "username"),
        ("courses", "code"),
    }
    assert (table, column) in allowed

    conn = db.get_connection()
    try:
        row = conn.execute(
            f"SELECT id FROM {table} WHERE {column} = ?",
            (value,),
        ).fetchone()
        assert row is not None
        return row["id"]
    finally:
        conn.close()


def uid(username):
    return lookup_id("users", "username", username)


def cid(code):
    return lookup_id("courses", "code", code)


def eid(username, code):
    conn = db.get_connection()
    try:
        row = conn.execute(
            """
            SELECT e.id
            FROM enrollments e
            JOIN users u ON u.id = e.student_id
            JOIN courses c ON c.id = e.course_id
            WHERE u.username = ? AND c.code = ?
            """,
            (username, code),
        ).fetchone()
        assert row is not None
        return row["id"]
    finally:
        conn.close()


def grade(enrollment_id):
    conn = db.get_connection()
    try:
        return conn.execute(
            "SELECT score FROM grades WHERE enrollment_id = ?",
            (enrollment_id,),
        ).fetchone()["score"]
    finally:
        conn.close()


def login_as(client, username):
    # Simulate a fully authenticated session after MFA.
    with client.session_transaction() as sess:
        sess.clear()
        sess["user_id"] = uid(username)
        sess["csrf_token"] = "test-csrf-token"


def update(client, enrollment_id, score, token="test-csrf-token"):
    return client.post(
        f"/instructor/grades/{enrollment_id}",
        data={"score": score, "csrf_token": token},
        follow_redirects=False,
    )


def test_anonymous_dashboard_denied(client):
    response = client.get("/instructor/")
    assert response.status_code == 401


def test_pending_mfa_dashboard_denied(client):
    with client.session_transaction() as sess:
        sess["pending_mfa_user_id"] = uid("instructor01")

    assert client.get("/instructor/").status_code == 401


@pytest.mark.parametrize("username", [
    "student01",
    "security01",
])
def test_other_roles_cannot_open_dashboard(client, username):
    login_as(client, username)
    assert client.get("/instructor/").status_code == 403


def test_instructor_can_view_assigned_course(client):
    login_as(client, "instructor01")

    response = client.get(
        f"/instructor/?course_id={cid('CS2413')}"
    )

    assert response.status_code == 200
    assert b"CS2413" in response.data
    assert b"student01" in response.data
    assert b"student02" in response.data
    assert b"student03" in response.data


def test_instructor_cannot_view_other_course(client):
    login_as(client, "instructor01")

    response = client.get(
        f"/instructor/?course_id={cid('CS2383')}"
    )
    assert response.status_code == 403


def test_authorized_grade_update(client):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")

    response = update(client, enrollment, "95")

    assert response.status_code == 302
    assert grade(enrollment) == 95


def test_cross_course_grade_update_denied(client):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2383")
    before = grade(enrollment)

    response = update(client, enrollment, "20")

    assert response.status_code == 403
    assert grade(enrollment) == before


@pytest.mark.parametrize("username", [
    "student01",
    "security01",
])
def test_other_roles_cannot_modify_grade(client, username):
    login_as(client, username)
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    assert update(client, enrollment, "50").status_code == 403
    assert grade(enrollment) == before


def test_anonymous_grade_update_denied(client):
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    assert update(client, enrollment, "50").status_code == 401
    assert grade(enrollment) == before


def test_pending_mfa_grade_update_denied(client):
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    with client.session_transaction() as sess:
        sess["pending_mfa_user_id"] = uid("instructor01")
        sess["csrf_token"] = "test-csrf-token"

    assert update(client, enrollment, "50").status_code == 401
    assert grade(enrollment) == before


@pytest.mark.parametrize("token", [
    "",
    "wrong-token",
])
def test_invalid_csrf_rejected(client, token):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    response = update(client, enrollment, "40", token)

    assert response.status_code == 400
    assert grade(enrollment) == before


def test_missing_csrf_rejected(client):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    response = client.post(
        f"/instructor/grades/{enrollment}",
        data={"score": "40"},
    )

    assert response.status_code == 400
    assert grade(enrollment) == before


@pytest.mark.parametrize("score", [
    "-1", "101", "80.5", "hello", "",
])
def test_invalid_grades_rejected(client, score):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    response = update(client, enrollment, score)

    assert response.status_code == 400
    assert grade(enrollment) == before


def test_nonexistent_enrollment_denied(client):
    login_as(client, "instructor01")

    response = update(client, 999999, "80")
    assert response.status_code == 403


def test_malformed_course_id_rejected(client):
    login_as(client, "instructor01")

    response = client.get(
        "/instructor/?course_id=1%20OR%201=1"
    )
    assert response.status_code == 400


def test_inactive_instructor_denied(client):
    login_as(client, "instructor01")

    conn = db.get_connection()
    try:
        conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (uid("instructor01"),),
        )
        conn.commit()
    finally:
        conn.close()

    assert client.get("/instructor/").status_code == 403

def test_grade_update_rejects_zero_and_leading_zero_values(client):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    for score in ("0000", "0001", "0100"):
        response = update(client, enrollment, score)
        assert response.status_code == 400
        assert grade(enrollment) == before


def test_inactive_instructor_cannot_update_grade(client):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    conn = db.get_connection()
    try:
        conn.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?",
            (uid("instructor01"),),
        )
        conn.commit()
    finally:
        conn.close()

    response = update(client, enrollment, "90")

    assert response.status_code == 403
    assert grade(enrollment) == before


def test_revoked_course_assignment_blocks_grade_update(client):
    login_as(client, "instructor01")
    enrollment = eid("student01", "CS2413")
    before = grade(enrollment)

    conn = db.get_connection()
    try:
        conn.execute(
            """
            DELETE FROM instructor_courses
            WHERE instructor_id = ? AND course_id = ?
            """,
            (uid("instructor01"), cid("CS2413")),
        )
        conn.commit()
    finally:
        conn.close()

    response = update(client, enrollment, "90")

    assert response.status_code == 403
    assert grade(enrollment) == before
