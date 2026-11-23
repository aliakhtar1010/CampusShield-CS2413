
"""Tests for secure grade management."""

import pytest

import db
from seed_demo import seed_database
from services.grade_service import (
    GradeNotFoundError,
    GradePermissionError,
    GradeValidationError,
    get_instructor_courses,
    get_course_students,
    update_grade,
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(
        db, "DB_PATH", tmp_path / "grade_service_test.db"
    )
    seed_database()
    connection = db.get_connection()

    connection.execute(
        "UPDATE users SET is_active = 1"
    )
    connection.commit()

    try:
        yield connection
    finally:
        connection.close()


def uid(conn, username):
    return conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,),
    ).fetchone()["id"]


def cid(conn, code):
    return conn.execute(
        "SELECT id FROM courses WHERE code = ?",
        (code,),
    ).fetchone()["id"]


def eid(conn, username, code):
    return conn.execute(
        """
        SELECT e.id
        FROM enrollments e
        JOIN users u ON u.id = e.student_id
        JOIN courses c ON c.id = e.course_id
        WHERE u.username = ? AND c.code = ?
        """,
        (username, code),
    ).fetchone()["id"]


def score_of(conn, enrollment_id):
    return conn.execute(
        "SELECT score FROM grades WHERE enrollment_id = ?",
        (enrollment_id,),
    ).fetchone()["score"]


def test_instructor_sees_only_assigned_courses(conn):
    courses = get_instructor_courses(
        conn, uid(conn, "instructor01")
    )
    assert [c["code"] for c in courses] == ["CS2413"]


def test_instructor_sees_assigned_course_students(conn):
    students = get_course_students(
        conn, uid(conn, "instructor01"),
        cid(conn, "CS2413"),
    )
    assert len(students) == 3
    assert all(s["score"] is not None for s in students)


def test_cross_course_student_listing_denied(conn):
    with pytest.raises(GradePermissionError):
        get_course_students(
            conn, uid(conn, "instructor01"),
            cid(conn, "CS2383"),
        )


def test_authorized_grade_update(conn):
    enrollment = eid(conn, "student01", "CS2413")
    assert update_grade(
        conn, uid(conn, "instructor01"), enrollment, 95
    )
    assert score_of(conn, enrollment) == 95


def test_cross_course_update_denied(conn):
    enrollment = eid(conn, "student01", "CS2383")
    before = score_of(conn, enrollment)

    with pytest.raises(GradeNotFoundError):
        update_grade(
            conn, uid(conn, "instructor01"), enrollment, 20
        )

    assert score_of(conn, enrollment) == before


@pytest.mark.parametrize("username", [
    "student01",
    "security01",
])
def test_other_roles_cannot_update(conn, username):
    enrollment = eid(conn, "student01", "CS2413")
    before = score_of(conn, enrollment)

    with pytest.raises(GradePermissionError):
        update_grade(conn, uid(conn, username), enrollment, 50)

    assert score_of(conn, enrollment) == before


@pytest.mark.parametrize("invalid_score", [
    -1, 101, 90.5, "90", None, True,
])
def test_invalid_scores_rejected(conn, invalid_score):
    enrollment = eid(conn, "student01", "CS2413")
    before = score_of(conn, enrollment)

    with pytest.raises(GradeValidationError):
        update_grade(
            conn, uid(conn, "instructor01"),
            enrollment, invalid_score,
        )

    assert score_of(conn, enrollment) == before


def test_invalid_enrollment_rejected(conn):
    with pytest.raises(GradeValidationError):
        update_grade(
            conn, uid(conn, "instructor01"),
            "1 OR 1=1", 80,
        )


def test_nonexistent_enrollment_denied(conn):
    with pytest.raises(GradeNotFoundError):
        update_grade(
            conn, uid(conn, "instructor01"), 999999, 80
        )


def test_inactive_instructor_cannot_update(conn):
    instructor = uid(conn, "instructor01")
    enrollment = eid(conn, "student01", "CS2413")
    before = score_of(conn, enrollment)

    conn.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (instructor,),
    )
    conn.commit()

    with pytest.raises(GradePermissionError):
        update_grade(conn, instructor, enrollment, 70)

    assert score_of(conn, enrollment) == before


def test_update_persists_after_reconnection(conn):
    instructor = uid(conn, "instructor01")
    enrollment = eid(conn, "student01", "CS2413")

    update_grade(conn, instructor, enrollment, 77)

    with db.get_connection() as second_connection:
        assert score_of(second_connection, enrollment) == 77
