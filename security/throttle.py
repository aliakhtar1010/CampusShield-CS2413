
import time

from db import get_connection


MAX_FAILURES = 5
WINDOW_SECONDS = 300
LOCKOUT_SECONDS = 300

VALID_STAGES = {"password", "mfa"}


def normalize_username(username):
    """Normalize usernames consistently."""
    if not isinstance(username, str):
        raise TypeError("Username must be a string")

    normalized = username.strip().lower()

    if not normalized or len(normalized) > 150:
        raise ValueError("Invalid username")

    return normalized


def validate_stage(stage):
    if stage not in VALID_STAGES:
        raise ValueError("Invalid authentication stage")


def current_timestamp(now=None):
    return int(time.time()) if now is None else int(now)


def get_auth_status(username, stage, now=None):
    """
    Return current authentication restriction state.

    Reads persistent SQLite state so restrictions
    survive application restarts.
    """
    username = normalize_username(username)
    validate_stage(stage)

    timestamp = current_timestamp(now)
    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT failure_count, window_started,
                   locked_until
            FROM auth_attempts
            WHERE username = ? AND stage = ?
        """, (username, stage)).fetchone()

        if row is None:
            return {
                "blocked": False,
                "failures": 0,
                "remaining": MAX_FAILURES,
                "retry_after": 0
            }

        if row["locked_until"] > timestamp:
            return {
                "blocked": True,
                "failures": row["failure_count"],
                "remaining": 0,
                "retry_after": (
                    row["locked_until"] - timestamp
                )
            }

        if (
            row["locked_until"] > 0
            or timestamp - row["window_started"]
                >= WINDOW_SECONDS
        ):
            failures = 0
        else:
            failures = row["failure_count"]

        return {
            "blocked": False,
            "failures": failures,
            "remaining": max(
                0, MAX_FAILURES - failures
            ),
            "retry_after": 0
        }

    finally:
        conn.close()


def record_auth_failure(username, stage, now=None):
    """
    Record a failed authentication attempt.

    Uses BEGIN IMMEDIATE to serialize database
    updates and prevent lost failure increments.
    """
    username = normalize_username(username)
    validate_stage(stage)

    timestamp = current_timestamp(now)
    conn = get_connection()

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT failure_count, window_started,
                   locked_until
            FROM auth_attempts
            WHERE username = ? AND stage = ?
        """, (username, stage)).fetchone()

        if row and row["locked_until"] > timestamp:
            conn.commit()
            return get_auth_status(
                username, stage, timestamp
            )

        if (
            row is None
            or row["locked_until"] > 0
            or timestamp - row["window_started"]
                >= WINDOW_SECONDS
        ):
            failures = 1
            window_started = timestamp
        else:
            failures = row["failure_count"] + 1
            window_started = row["window_started"]

        locked_until = (
            timestamp + LOCKOUT_SECONDS
            if failures >= MAX_FAILURES
            else 0
        )

        conn.execute("""
            INSERT INTO auth_attempts (
                username, stage, failure_count,
                window_started, locked_until,
                last_failure
            )
            VALUES (?, ?, ?, ?, ?, ?)

            ON CONFLICT(username, stage)
            DO UPDATE SET
                failure_count = excluded.failure_count,
                window_started = excluded.window_started,
                locked_until = excluded.locked_until,
                last_failure = excluded.last_failure
        """, (
            username,
            stage,
            failures,
            window_started,
            locked_until,
            timestamp
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return get_auth_status(username, stage, timestamp)


def reset_auth_failures(username, stage):
    """
    Clear the failure counter after the
    relevant authentication stage succeeds.
    """
    username = normalize_username(username)
    validate_stage(stage)

    conn = get_connection()

    try:
        conn.execute("""
            DELETE FROM auth_attempts
            WHERE username = ? AND stage = ?
        """, (username, stage))

        conn.commit()

    finally:
        conn.close()
