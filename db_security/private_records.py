"""Least-privilege SQLite access for encrypted fictional student contacts.

Use only after the Flask app has completed authentication. The caller MUST pass
``authenticated_user_id`` from the server-managed session, never from form data
or an HTTP request parameter. Role and active state are rechecked in SQLite.

Functions accept an already-open database connection for isolation and testing.
They do not commit or close it: the caller owns commit/rollback and connection
lifecycle. No existing CampusShield tables, routes, or modules are modified.
"""

from db_security.field_encryption import decrypt_field, encrypt_field


class PrivateRecordAccessDenied(PermissionError):
    """The authenticated account cannot access the requested student record."""


class PrivateRecordNotFound(LookupError):
    """The authenticated student has no private contact record yet."""


def _check_identity(authenticated_user_id: int, student_id: int) -> None:
    """Reject fabricated or cross-student identifiers before running SQL."""
    # SQLite INTEGER supports signed 64-bit values. Reject overflow before SQL.
    max_sqlite_id = 9223372036854775807
    if (
        type(authenticated_user_id) is not int
        or not 0 < authenticated_user_id <= max_sqlite_id
    ):
        raise ValueError("Invalid authenticated user ID")
    if type(student_id) is not int or not 0 < student_id <= max_sqlite_id:
        raise ValueError("Invalid student ID")
    if authenticated_user_id != student_id:
        raise PrivateRecordAccessDenied("Private record access denied")


def _require_active_student(conn, authenticated_user_id: int) -> None:
    """Read trusted role/status from users, never from browser-supplied roles."""
    eligible = conn.execute(
        """SELECT 1 FROM users
           WHERE id = ? AND role = 'student' AND is_active = 1""",
        (authenticated_user_id,),
    ).fetchone()
    if eligible is None:
        raise PrivateRecordAccessDenied("Private record access denied")


def save_private_record(
    conn,
    *,
    authenticated_user_id: int,
    student_id: int,
    email: str,
    phone: str,
) -> None:
    """Insert or update only the authenticated active student's own fields.

    Both fields are validated and encrypted *before* either is written.
    The write statement itself also verifies the user is an active student,
    preventing a role/status change between the preliminary check and write.

    The caller must call conn.commit() after success; on error, roll back
    the caller's transaction. This function never stores plaintext.
    """
    _check_identity(authenticated_user_id, student_id)
    _require_active_student(conn, authenticated_user_id)

    encrypted_email = encrypt_field(student_id, "email", email)
    encrypted_phone = encrypt_field(student_id, "phone", phone)

    # No untrusted value is interpolated into SQL. The INSERT and UPDATE
    # branches both recheck eligibility as part of the same SQL statement.
    result = conn.execute(
        """INSERT INTO student_private_records
               (student_id, encrypted_email, encrypted_phone)
           SELECT ?, ?, ?
           WHERE EXISTS (
               SELECT 1 FROM users
               WHERE id = ? AND role = 'student' AND is_active = 1
           )
           ON CONFLICT(student_id) DO UPDATE SET
               encrypted_email = excluded.encrypted_email,
               encrypted_phone = excluded.encrypted_phone,
               updated_at = CURRENT_TIMESTAMP
           WHERE EXISTS (
               SELECT 1 FROM users
               WHERE id = excluded.student_id
                 AND role = 'student' AND is_active = 1
           )""",
        (
            student_id,
            encrypted_email,
            encrypted_phone,
            authenticated_user_id,
        ),
    )
    if result.rowcount != 1:
        raise PrivateRecordAccessDenied("Private record access denied")


def get_private_record(
    conn, *, authenticated_user_id: int, student_id: int
) -> dict[str, str]:
    """Return decrypted contact fields only for their authenticated owner.

    One parameterized JOIN checks ownership, active status, and role as part
    of retrieval. Decryption occurs only *after* the authorized query succeeds.
    Corrupt/misbound ciphertext raises PrivateFieldDecryptionError from the
    field encryption module; no partial record is returned.
    """
    _check_identity(authenticated_user_id, student_id)

    row = conn.execute(
        """SELECT p.encrypted_email, p.encrypted_phone
           FROM student_private_records AS p
           JOIN users AS u ON u.id = p.student_id
           WHERE p.student_id = ? AND u.id = ?
             AND u.role = 'student' AND u.is_active = 1""",
        (student_id, authenticated_user_id),
    ).fetchone()

    if row is None:
        # Distinguish an authorized account with no record from an account
        # that must not access these values. Neither case reveals ciphertext.
        _require_active_student(conn, authenticated_user_id)
        raise PrivateRecordNotFound("Private contact record not found")

    return {
        "email": decrypt_field(student_id, "email", row["encrypted_email"]),
        "phone": decrypt_field(student_id, "phone", row["encrypted_phone"]),
    }
