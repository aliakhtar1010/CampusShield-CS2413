
import sqlite3
import sys
from pathlib import Path

import pytest

# Make project modules importable from the tests directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db import get_connection


@pytest.fixture
def conn():
    connection = get_connection()
    yield connection
    connection.rollback()
    connection.close()


def test_foreign_keys_enabled(conn):
    """Verify database relationship enforcement."""
    result = conn.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0]

    assert result == 1


def test_invalid_grade_rejected(conn):
    """A grade cannot exceed the allowed range."""
    enrollment = conn.execute("""
        SELECT id FROM enrollments
        LIMIT 1
    """).fetchone()

    assert enrollment is not None

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("""
            INSERT INTO grades (enrollment_id, score)
            VALUES (?, ?)
        """, (enrollment["id"], 150))


def test_duplicate_enrollment_rejected(conn):
    """A student cannot enroll twice in one course."""
    enrollment = conn.execute("""
        SELECT student_id, course_id
        FROM enrollments
        LIMIT 1
    """).fetchone()

    assert enrollment is not None

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("""
            INSERT INTO enrollments (student_id, course_id)
            VALUES (?, ?)
        """, (
            enrollment["student_id"],
            enrollment["course_id"]
        ))


def test_invalid_student_reference_rejected(conn):
    """Enrollment must reference an existing student."""
    course = conn.execute(
        "SELECT id FROM courses LIMIT 1"
    ).fetchone()

    assert course is not None

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("""
            INSERT INTO enrollments
            (student_id, course_id)
            VALUES (?, ?)
        """, (-99999, course["id"]))


def test_seeded_records_available(conn):
    """Confirm expected fictional academic data exists."""
    records = conn.execute("""
        SELECT c.code, g.score
        FROM grades g
        JOIN enrollments e ON g.enrollment_id = e.id
        JOIN courses c ON e.course_id = c.id
        JOIN users u ON e.student_id = u.id
        WHERE u.username = ?
        ORDER BY c.code
    """, ("student01",)).fetchall()

    assert [(r["code"], r["score"]) for r in records] == [
        ("CS2383", 94),
        ("CS2413", 88)
    ]
