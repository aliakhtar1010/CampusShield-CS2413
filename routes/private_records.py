"""Student-only UI for encrypted fictional private contact information.

Identity is taken exclusively from a fully authenticated Flask session.
This route never accepts a client-controlled student ID or account role.
"""

import sqlite3
from hmac import compare_digest

from flask import (
    Blueprint,
    abort,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import get_connection
from db_security.field_encryption import (
    PrivateFieldConfigurationError,
    PrivateFieldDecryptionError,
)
from db_security.private_records import (
    PrivateRecordAccessDenied,
    PrivateRecordNotFound,
    get_private_record,
    save_private_record,
)
from security.authorization import authenticated_user_id, get_user, ROLE_STUDENT


private_records_bp = Blueprint(
    "private_records", __name__, url_prefix="/private-records"
)


def _require_student(conn):
    """Reject unauthenticated, pending-MFA, inactive and nonstudent users."""
    user_id = authenticated_user_id()
    if user_id is None:
        abort(401)

    user = get_user(conn, user_id)
    if user is None or user["role"] != ROLE_STUDENT:
        abort(403)

    return user


def _require_csrf():
    submitted = request.form.get("csrf_token")
    expected = session.get("csrf_token")
    if (
        not isinstance(expected, str)
        or not isinstance(submitted, str)
        or not expected
        or not compare_digest(expected, submitted)
    ):
        abort(400)


def _private_response(*, user, email="", phone="", error=None, saved=False, status=200):
    """Don't cache decrypted private contact values in browser/proxy caches."""
    response = make_response(
        render_template(
            "private_record.html",
            user=user,
            email=email,
            phone=phone,
            error=error,
            saved=saved,
        ),
        status,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@private_records_bp.route("/", methods=["GET", "POST"])
def contact():
    conn = get_connection()
    try:
        user = _require_student(conn)
        student_id = user["id"]  # Never use request.form/args for ownership.

        if request.method == "POST":
            _require_csrf()
            email = request.form.get("email", "")
            phone = request.form.get("phone", "")
            try:
                save_private_record(
                    conn,
                    authenticated_user_id=student_id,
                    student_id=student_id,
                    email=email,
                    phone=phone,
                )
                conn.commit()
            except ValueError:
                conn.rollback()
                return _private_response(
                    user=user,
                    email=email,
                    phone=phone,
                    error="Enter a valid email and an E.164 phone number (e.g. +15065550123).",
                    status=400,
                )

            return redirect(url_for("private_records.contact", saved="1"))

        try:
            record = get_private_record(
                conn,
                authenticated_user_id=student_id,
                student_id=student_id,
            )
        except PrivateRecordNotFound:
            record = {"email": "", "phone": ""}

        return _private_response(
            user=user,
            email=record["email"],
            phone=record["phone"],
            saved=request.args.get("saved") == "1",
        )

    except PrivateRecordAccessDenied:
        conn.rollback()
        abort(403)
    except (
        PrivateFieldConfigurationError,
        PrivateFieldDecryptionError,
        sqlite3.OperationalError,
    ):
        # Missing migration, unavailable key, and ciphertext corruption
        # never reveal plaintext, ciphertext or internal exception details.
        conn.rollback()
        abort(503)
    finally:
        conn.close()
