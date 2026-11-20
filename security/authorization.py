
"""Centralized CampusShield authorization policy.

Callers must use a fully authenticated session identity,
not an identity or role supplied by the browser.
"""

from flask import session

ROLE_STUDENT = "student"
ROLE_INSTRUCTOR = "instructor"
ROLE_SECURITY_ADMIN = "security_admin"


def authenticated_user_id():
    """Return a fully authenticated user ID, or None."""
    user_id = session.get("user_id")
    if type(user_id) is not int or user_id <= 0:
        return None
    return user_id


def get_user(conn, user_id):
    """Look up an active user's trusted database role."""
    if type(user_id) is not int or user_id <= 0:
        return None

    return conn.execute(
        "SELECT id, username, full_name, role FROM users "
        "WHERE id = ? AND is_active = 1",
        (user_id,),
    ).fetchone()


def has_role(conn, user_id, role):
    """Check the user's role against the database."""
    user = get_user(conn, user_id)
    return user is not None and user["role"] == role


def can_view_record(conn, user_id, student_id):
    """Students may view only their own records."""
    return (
        type(student_id) is int
        and student_id > 0
        and user_id == student_id
        and has_role(conn, user_id, ROLE_STUDENT)
    )


def can_manage_course(conn, user_id, course_id):
    """Instructors may manage only assigned courses."""
    if type(course_id) is not int or course_id <= 0:
        return False

    if not has_role(conn, user_id, ROLE_INSTRUCTOR):
        return False

    return conn.execute(
        "SELECT 1 FROM instructor_courses "
        "WHERE instructor_id = ? AND course_id = ?",
        (user_id, course_id),
    ).fetchone() is not None


def can_update_grade(conn, user_id, enrollment_id):
    """Allow grade updates only within assigned courses."""
    if type(enrollment_id) is not int or enrollment_id <= 0:
        return False

    if not has_role(conn, user_id, ROLE_INSTRUCTOR):
        return False

    return conn.execute(
        "SELECT 1 FROM enrollments e "
        "JOIN instructor_courses ic ON ic.course_id = e.course_id "
        "WHERE e.id = ? AND ic.instructor_id = ?",
        (enrollment_id, user_id),
    ).fetchone() is not None
