
"""Authorization tests using isolated temporary databases."""

import sys
from pathlib import Path

import pytest
from flask import Flask, session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db
from seed_demo import seed_database
from security.authorization import (
    authenticated_user_id,
    can_manage_course,
    can_update_grade,
    can_view_record,
    get_user,
    has_role,
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(
        db, "DB_PATH", tmp_path / "authorization_test.db"
    )
    seed_database()
    connection = db.get_connection()

    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()


def user_id(conn, username):
    return conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,),
    ).fetchone()["id"]


def course_id(conn, code):
    return conn.execute(
        "SELECT id FROM courses WHERE code = ?",
        (code,),
    ).fetchone()["id"]


def enrollment_id(conn, student, course):
    return conn.execute(
        "SELECT e.id FROM enrollments e "
        "JOIN users u ON u.id = e.student_id "
        "JOIN courses c ON c.id = e.course_id "
        "WHERE u.username = ? AND c.code = ?",
        (student, course),
    ).fetchone()["id"]


def activate(conn, *usernames):
    for username in usernames:
        conn.execute(
            "UPDATE users SET is_active = 1 "
            "WHERE username = ?",
            (username,),
        )


def test_pending_mfa_is_not_authenticated():
    app = Flask(__name__)
    app.secret_key = "test-only-session-key"

    with app.test_request_context("/"):
        session["pending_mfa_user_id"] = 10
        assert authenticated_user_id() is None

        session["user_id"] = 10
        assert authenticated_user_id() == 10

        session["user_id"] = "10"
        assert authenticated_user_id() is None


def test_inactive_users_are_denied(conn):
    student = user_id(conn, "student01")
    instructor = user_id(conn, "instructor01")

    assert get_user(conn, student) is None
    assert not can_view_record(conn, student, student)
    assert not can_manage_course(
        conn, instructor, course_id(conn, "CS2413")
    )


def test_student_can_only_view_own_record(conn):
    activate(
        conn, "student01", "student02",
        "instructor01", "security01"
    )

    student1 = user_id(conn, "student01")
    student2 = user_id(conn, "student02")

    assert has_role(conn, student1, "student")
    assert can_view_record(conn, student1, student1)
    assert not can_view_record(conn, student1, student2)

    assert not can_view_record(
        conn, user_id(conn, "instructor01"), student1
    )
    assert not can_view_record(
        conn, user_id(conn, "security01"), student1
    )


def test_instructor_is_limited_to_assigned_course(conn):
    activate(
        conn, "instructor01", "instructor02",
        "student01", "security01"
    )

    instructor1 = user_id(conn, "instructor01")
    instructor2 = user_id(conn, "instructor02")
    cs2413 = course_id(conn, "CS2413")
    cs2383 = course_id(conn, "CS2383")

    assert can_manage_course(conn, instructor1, cs2413)
    assert not can_manage_course(conn, instructor1, cs2383)

    assert can_manage_course(conn, instructor2, cs2383)
    assert not can_manage_course(conn, instructor2, cs2413)

    assert not can_manage_course(
        conn, user_id(conn, "student01"), cs2413
    )
    assert not can_manage_course(
        conn, user_id(conn, "security01"), cs2413
    )


def test_grade_authorization_rejects_cross_course_and_other_roles(conn):
    activate(
        conn, "instructor01", "instructor02",
        "student01", "security01"
    )

    cs2413_grade = enrollment_id(
        conn, "student01", "CS2413"
    )
    cs2383_grade = enrollment_id(
        conn, "student01", "CS2383"
    )
    instructor = user_id(conn, "instructor01")

    assert can_update_grade(conn, instructor, cs2413_grade)
    assert not can_update_grade(
        conn, instructor, cs2383_grade
    )

    assert not can_update_grade(
        conn, user_id(conn, "student01"), cs2413_grade
    )
    assert not can_update_grade(
        conn, user_id(conn, "security01"), cs2413_grade
    )

    assert not can_update_grade(conn, instructor, 999999)
    assert not can_update_grade(
        conn, instructor, "1 OR 1=1"
    )


def test_deactivated_instructor_loses_access(conn):
    activate(conn, "instructor01")

    instructor = user_id(conn, "instructor01")
    grade = enrollment_id(
        conn, "student01", "CS2413"
    )

    assert can_update_grade(conn, instructor, grade)

    conn.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (instructor,),
    )

    assert not can_update_grade(conn, instructor, grade)
