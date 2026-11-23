
import os
import secrets
import time

from datetime import timedelta
from functools import wraps
from hmac import compare_digest

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for
)

from db import get_connection
from routes.instructor import instructor_bp
from security.passwords import verify_password
from security.encryption import decrypt_secret
from security.mfa import verify_mfa_code
from security.throttle import (
    get_auth_status,
    record_auth_failure,
    reset_auth_failures
)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

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

PRIVILEGED_ROLES = {"instructor", "security_admin"}

MFA_CHALLENGE_TIMEOUT = 300
MAX_MFA_ATTEMPTS = 5

LOCKOUT_MESSAGE = (
    "Too many authentication attempts. "
    "Please try again later."
)


# ==========================================
# CSRF PROTECTION
# ==========================================

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token

# Register Phase 3 instructor routes.
app.register_blueprint(instructor_bp)


def valid_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")

    return (
        bool(expected)
        and compare_digest(submitted, expected)
    )


# ==========================================
# AUTHENTICATED USER
# ==========================================

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


# ==========================================
# SESSION MANAGEMENT
# ==========================================

def establish_session(user_id):
    session.clear()

    session["user_id"] = user_id
    session["authenticated_at"] = int(time.time())
    session.permanent = True

    csrf_token()


def start_mfa_challenge(user_id):
    session.clear()

    session["pending_mfa_user_id"] = user_id
    session["pending_mfa_started"] = int(time.time())
    session["mfa_attempts"] = 0
    session.permanent = True

    csrf_token()


def clear_expired_mfa_challenge():
    started = session.get("pending_mfa_started")
    attempts = session.get("mfa_attempts", 0)

    if not isinstance(started, int):
        session.clear()
        return True

    if not isinstance(attempts, int):
        session.clear()
        return True

    elapsed = time.time() - started

    if elapsed < 0 or elapsed > MFA_CHALLENGE_TIMEOUT:
        session.clear()
        return True

    if attempts >= MAX_MFA_ATTEMPTS:
        session.clear()
        return True

    return False


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():
    return render_template(
        "index.html",
        user=current_user()
    )


# ==========================================
# PASSWORD LOGIN + PERSISTENT THROTTLING
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        if not valid_csrf():
            abort(400)

        username = request.form.get(
            "username", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        # Validate username before querying the database
        # or creating throttling records.
        if not username or len(username) > 150:
            error = "Invalid username or password."

        else:
            status = get_auth_status(
                username, "password"
            )

            if status["blocked"]:
                error = LOCKOUT_MESSAGE

            else:
                conn = get_connection()

                try:
                    user = conn.execute("""
                        SELECT id, username, role,
                               password_hash, is_active
                        FROM users
                        WHERE username = ?
                    """, (username,)).fetchone()

                    authenticated = (
                        user is not None
                        and user["is_active"] == 1
                        and verify_password(
                            user["password_hash"],
                            password
                        )
                    )

                    if not authenticated:
                        status = record_auth_failure(
                            username, "password"
                        )

                        error = (
                            LOCKOUT_MESSAGE
                            if status["blocked"]
                            else "Invalid username or password."
                        )

                    elif user["role"] in PRIVILEGED_ROLES:
                        # Check MFA enrollment before
                        # issuing a pending challenge.
                        credential = conn.execute("""
                            SELECT is_enabled
                            FROM mfa_credentials
                            WHERE user_id = ?
                        """, (user["id"],)).fetchone()

                        if (
                            credential is None
                            or credential["is_enabled"] != 1
                        ):
                            error = (
                                "MFA enrollment is required "
                                "for this account."
                            )

                        else:
                            # Successful first factor.
                            reset_auth_failures(
                                username, "password"
                            )

                            # Do not create fresh MFA challenges
                            # while the account is MFA-locked.
                            mfa_status = get_auth_status(
                                username, "mfa"
                            )

                            if mfa_status["blocked"]:
                                error = LOCKOUT_MESSAGE

                            else:
                                start_mfa_challenge(user["id"])

                                return redirect(
                                    url_for("verify_mfa")
                                )

                    elif user["role"] == "student":
                        reset_auth_failures(
                            username, "password"
                        )

                        establish_session(user["id"])

                        return redirect(
                            url_for("academic_records")
                        )

                    else:
                        error = "Authentication unavailable."

                finally:
                    conn.close()

    return render_template(
        "login.html",
        error=error
    )


# ==========================================
# MFA VERIFICATION + PERSISTENT THROTTLING
# ==========================================

@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    if current_user() is not None:
        return redirect(url_for("home"))

    pending_user_id = session.get(
        "pending_mfa_user_id"
    )

    if pending_user_id is None:
        return redirect(url_for("login"))

    if clear_expired_mfa_challenge():
        return redirect(url_for("login"))

    conn = get_connection()

    try:
        account = conn.execute("""
            SELECT
                u.id,
                u.username,
                u.role,
                u.is_active,
                m.encrypted_secret,
                m.last_used_step,
                m.is_enabled
            FROM users u
            JOIN mfa_credentials m
                ON m.user_id = u.id
            WHERE u.id = ?
        """, (pending_user_id,)).fetchone()

        if (
            account is None
            or account["is_active"] != 1
            or account["is_enabled"] != 1
            or account["role"] not in PRIVILEGED_ROLES
        ):
            session.clear()
            return redirect(url_for("login"))

        username = account["username"]

        # Recheck persistent restrictions on every request.
        status = get_auth_status(username, "mfa")

        if status["blocked"]:
            session.clear()
            return redirect(url_for("login"))

        error = None

        if request.method == "POST":
            if not valid_csrf():
                abort(400)

            code = request.form.get(
                "code", ""
            ).strip()

            matched_step = None

            try:
                decrypted_secret = decrypt_secret(
                    account["encrypted_secret"]
                )

                matched_step = verify_mfa_code(
                    decrypted_secret,
                    code,
                    last_used_step=account["last_used_step"]
                )

            except (ValueError, RuntimeError):
                # Fail closed if a secret cannot be
                # decrypted or verified.
                matched_step = None

            if matched_step is not None:
                # Atomic replay protection.
                cursor = conn.execute("""
                    UPDATE mfa_credentials
                    SET last_used_step = ?
                    WHERE user_id = ?
                      AND is_enabled = 1
                      AND last_used_step < ?
                """, (
                    matched_step,
                    pending_user_id,
                    matched_step
                ))

                if cursor.rowcount == 1:
                    conn.commit()

                    reset_auth_failures(
                        username, "mfa"
                    )

                    establish_session(
                        pending_user_id
                    )

                    return redirect(
                        url_for("home")
                    )

                conn.rollback()

            # Failed second-factor verification.
            status = record_auth_failure(
                username, "mfa"
            )

            session["mfa_attempts"] = (
                session.get("mfa_attempts", 0) + 1
            )

            attempts_remaining = (
                MAX_MFA_ATTEMPTS
                - session["mfa_attempts"]
            )

            if (
                status["blocked"]
                or attempts_remaining <= 0
            ):
                session.clear()
                return redirect(
                    url_for("login")
                )

            error = (
                "Invalid or previously used MFA code. "
                f"{attempts_remaining} attempts remaining."
            )

        return render_template(
            "verify_mfa.html",
            error=error,
            attempts_remaining=(
                MAX_MFA_ATTEMPTS
                - session.get("mfa_attempts", 0)
            )
        )

    finally:
        conn.close()


# ==========================================
# PROTECTED STUDENT ACADEMIC RECORDS
# ==========================================

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


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf():
        abort(400)

    session.clear()

    return redirect(url_for("login"))


# ==========================================
# LOCAL DEVELOPMENT
# ==========================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1"
    )
