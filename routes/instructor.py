
"""Instructor dashboard and secure grade-update routes."""

from hmac import compare_digest

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import get_connection
from security.audit_integration import record_security_event
from security.authorization import (
    authenticated_user_id,
    get_user,
    ROLE_INSTRUCTOR,
)
from services.grade_service import (
    GradeNotFoundError,
    GradePermissionError,
    GradeValidationError,
    get_instructor_courses,
    get_course_students,
    update_grade,
)

instructor_bp = Blueprint(
    "instructor",
    __name__,
    url_prefix="/instructor",
)


def require_instructor(conn):
    """Require a fully authenticated, active instructor."""
    user_id = authenticated_user_id()

    if user_id is None:
        abort(401)

    user = get_user(conn, user_id)

    if user is None or user["role"] != ROLE_INSTRUCTOR:
        record_security_event(
            "access_denied",
            actor_id=user_id,
            target_type="resource",
            outcome="denied",
            metadata={
                "reason": "wrong_role",
            },
        )
        abort(403)

    return user


def require_csrf():
    """Validate the existing session CSRF token."""
    expected = session.get("csrf_token")
    submitted = request.form.get("csrf_token")

    if (
        not isinstance(expected, str)
        or not isinstance(submitted, str)
        or not expected
        or not compare_digest(expected, submitted)
    ):
        abort(400)


def parse_positive_id(value):
    """Accept only positive decimal identifiers."""
    if not isinstance(value, str) or not value.isascii():
        abort(400)

    if not value.isdecimal() or len(value) > 18:
        abort(400)

    number = int(value)

    if number <= 0:
        abort(400)

    return number


@instructor_bp.get("/")
def dashboard():
    conn = get_connection()

    try:
        user = require_instructor(conn)
        courses = get_instructor_courses(conn, user["id"])

        selected_course = request.args.get("course_id")
        students = []
        course_id = None

        if selected_course is not None:
            course_id = parse_positive_id(selected_course)

            try:
                students = get_course_students(
                    conn, user["id"], course_id
                )

            except GradePermissionError:
                record_security_event(
                    "access_denied",
                    actor_id=user["id"],
                    target_type="course",
                    target_id=course_id,
                    outcome="denied",
                    metadata={
                        "reason": "not_assigned",
                    },
                )
                abort(403)

        return render_template(
            "instructor_dashboard.html",
            user=user,
            courses=courses,
            students=students,
            selected_course_id=course_id,
        )

    except GradePermissionError:
        abort(403)
    except GradeValidationError:
        abort(400)
    finally:
        conn.close()


@instructor_bp.post("/grades/<int:enrollment_id>")
def change_grade(enrollment_id):
    conn = get_connection()

    try:
        user = require_instructor(conn)
        require_csrf()

        if enrollment_id <= 0:
            abort(400)

        raw_score = request.form.get("score", "")

        if (
            not raw_score.isascii()
            or not raw_score.isdecimal()
            or len(raw_score) > 3
        ):
            abort(400)

        score = int(raw_score)

        try:
            update_grade(
                conn,
                user["id"],
                enrollment_id,
                score,
            )

        except (GradePermissionError, GradeNotFoundError):
            record_security_event(
                "grade_update",
                actor_id=user["id"],
                target_type="grade",
                target_id=enrollment_id,
                outcome="denied",
                metadata={
                    "reason": "not_assigned",
                },
            )
            abort(403)

        # update_grade commits before returning.
        # The audit write uses its separate protected database.
        record_security_event(
            "grade_update",
            actor_id=user["id"],
            target_type="grade",
            target_id=enrollment_id,
            outcome="success",
        )

        return redirect(
            url_for("instructor.dashboard")
        )

    except GradeValidationError:
        abort(400)
    finally:
        conn.close()
