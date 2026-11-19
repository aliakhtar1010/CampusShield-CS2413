
import os
import secrets
from datetime import timedelta
from functools import wraps
from hmac import compare_digest

from flask import (
    Flask, abort, redirect, render_template,
    request, session, url_for
)

from db import get_connection
from security.passwords import verify_password


app = Flask(__name__)

secret_key = os.environ.get("CAMPUSSHIELD_SECRET_KEY")

if not secret_key or len(secret_key) < 32:
    raise RuntimeError(
        "Set CAMPUSSHIELD_SECRET_KEY to a strong random value."
    )

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Local HTTP only
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def valid_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")

    return bool(expected) and compare_digest(
        submitted, expected
    )


def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    conn = get_connection()

    try:
        return conn.execute("""
            SELECT id, username, full_name, role
            FROM users
            WHERE id = ? AND is_active = 1
        """, (user_id,)).fetchone()
    finally:
        conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            session.clear()
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def home():
    return render_template(
        "index.html",
        user=current_user()
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(url_for("academic_records"))

    error = None

    if request.method == "POST":
        if not valid_csrf():
            abort(400)

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        conn = get_connection()

        try:
            user = conn.execute("""
                SELECT id, username, role,
                       password_hash, is_active
                FROM users
                WHERE username = ?
            """, (username,)).fetchone()
        finally:
            conn.close()

        authenticated = (
            user is not None
            and user["is_active"] == 1
            and verify_password(
                user["password_hash"], password
            )
        )

        if not authenticated:
            error = "Invalid username or password."

        elif user["role"] != "student":
            # Privileged accounts must not bypass MFA.
            # Their login will be enabled in Phase 2.4.
            error = "Privileged account login is not enabled yet."

        else:
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            csrf_token()

            return redirect(
                url_for("academic_records")
            )

    return render_template(
        "login.html",
        error=error
    )


@app.route("/records")
@login_required
def academic_records():
    user = current_user()

    if user["role"] != "student":
        abort(403)

    conn = get_connection()

    try:
        records = conn.execute("""
            SELECT
                u.full_name AS student_name,
                c.code AS course_code,
                c.title AS course_title,
                g.score AS grade
            FROM grades g
            JOIN enrollments e
                ON g.enrollment_id = e.id
            JOIN users u
                ON e.student_id = u.id
            JOIN courses c
                ON e.course_id = c.id
            WHERE u.id = ?
            ORDER BY c.code
        """, (user["id"],)).fetchall()
    finally:
        conn.close()

    return render_template(
        "records.html",
        records=records,
        user=user
    )


@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf():
        abort(400)

    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1")
