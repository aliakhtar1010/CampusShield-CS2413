
"""Secure, course-scoped grade management for CampusShield."""

from security.authorization import (
    can_manage_course,
    has_role,
    ROLE_INSTRUCTOR,
)


class GradePermissionError(PermissionError):
    """The user is not authorized to perform this action."""


class GradeValidationError(ValueError):
    """The requested grade or identifier is invalid."""


class GradeNotFoundError(LookupError):
    """No matching authorized enrollment or grade exists."""


def _valid_id(value):
    return type(value) is int and value > 0


def get_instructor_courses(conn, instructor_id):
    """Return courses assigned to an active instructor."""
    if not has_role(conn, instructor_id, ROLE_INSTRUCTOR):
        raise GradePermissionError("Instructor access required")

    return conn.execute(
        """
        SELECT c.id, c.code, c.title
        FROM courses c
        JOIN instructor_courses ic ON ic.course_id = c.id
        WHERE ic.instructor_id = ?
        ORDER BY c.code
        """,
        (instructor_id,),
    ).fetchall()


def get_course_students(conn, instructor_id, course_id):
    """Return enrolled students and grades for an assigned course."""
    if not _valid_id(course_id):
        raise GradeValidationError("Invalid course ID")

    if not can_manage_course(conn, instructor_id, course_id):
        raise GradePermissionError("Course access denied")

    return conn.execute(
        """
        SELECT e.id AS enrollment_id,
               u.id AS student_id,
               u.username,
               u.full_name,
               g.score,
               g.updated_at
        FROM enrollments e
        JOIN users u ON u.id = e.student_id
        LEFT JOIN grades g ON g.enrollment_id = e.id
        WHERE e.course_id = ?
          AND u.role = 'student'
        ORDER BY u.full_name
        """,
        (course_id,),
    ).fetchall()


def update_grade(conn, instructor_id, enrollment_id, score):
    """Atomically update a grade only for an assigned instructor.

    The caller must obtain instructor_id from a fully authenticated
    server-side session, never from request form data.
    """
    if not _valid_id(enrollment_id):
        raise GradeValidationError("Invalid enrollment ID")

    if type(score) is not int or not 0 <= score <= 100:
        raise GradeValidationError(
            "Grade must be an integer between 0 and 100"
        )

    if not has_role(conn, instructor_id, ROLE_INSTRUCTOR):
        raise GradePermissionError("Instructor access required")

    with conn:
        cursor = conn.execute(
            """
            UPDATE grades
            SET score = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE enrollment_id = ?
              AND EXISTS (
                  SELECT 1
                  FROM enrollments e
                  JOIN instructor_courses ic
                    ON ic.course_id = e.course_id
                  JOIN users u
                    ON u.id = ic.instructor_id
                  WHERE e.id = grades.enrollment_id
                    AND e.id = ?
                    AND ic.instructor_id = ?
                    AND u.role = 'instructor'
                    AND u.is_active = 1
              )
            """,
            (score, enrollment_id, enrollment_id, instructor_id),
        )

        if cursor.rowcount != 1:
            raise GradeNotFoundError(
                "No grade found within authorized courses"
            )

    return True
