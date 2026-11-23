"""Authenticated encryption of fictional student contact fields.

This module does not connect to SQLite or authorize a request. The caller must
verify the user's identity and access rights before calling decrypt_field.

Fernet authenticates ciphertext. The encrypted JSON envelope also binds every
value to its student ID and field name to reject ciphertext transplantation.
"""

import json
import re

from cryptography.fernet import InvalidToken

from security.encryption import get_cipher


class PrivateFieldConfigurationError(RuntimeError):
    """The application's encryption key is missing or invalid."""


class PrivateFieldDecryptionError(ValueError):
    """A private field cannot be decrypted or fails its integrity checks."""


# Keep accepted fields fixed. Never treat a user-supplied field name as SQL.
_FIELD_NAMES = frozenset({"email", "phone"})
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\Z")
_PHONE_RE = re.compile(r"\+[1-9][0-9]{7,14}\Z")
_ENVELOPE_VERSION = 1
_MAX_TOKEN_LENGTH = 4096  # Matches the migration's encrypted-column checks.


def _validate_context(student_id: int, field_name: str) -> None:
    if type(student_id) is not int or student_id <= 0:
        raise ValueError("Invalid student ID")
    if not isinstance(field_name, str) or field_name not in _FIELD_NAMES:
        raise ValueError("Unsupported private field")


def validate_private_value(field_name: str, value: str) -> str:
    """Validate one fictional contact value without silently modifying it.

    Email: simplified web-form validation, not full RFC 5322 parsing.
    Phone: E.164-style international number (+ followed by 8 to 15 digits).
    """
    if not isinstance(field_name, str) or field_name not in _FIELD_NAMES:
        raise ValueError("Unsupported private field")
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Invalid private field value")
    if field_name == "email":
        if len(value) > 254 or _EMAIL_RE.fullmatch(value) is None:
            raise ValueError("Invalid private email address")
    elif _PHONE_RE.fullmatch(value) is None:
        raise ValueError("Invalid private phone number")
    return value


def _get_cipher():
    """Reuse Ali's key loader, converting configuration errors to a local type."""
    try:
        return get_cipher()
    except (RuntimeError, UnicodeError) as exc:
        raise PrivateFieldConfigurationError(
            "Private-field encryption key is missing or invalid"
        ) from exc


def encrypt_field(student_id: int, field_name: str, value: str) -> str:
    """Return an ASCII Fernet token; never return/store plaintext as fallback."""
    _validate_context(student_id, field_name)
    validated = validate_private_value(field_name, value)

    envelope = {
        "version": _ENVELOPE_VERSION,
        "student_id": student_id,
        "field": field_name,
        "value": validated,
    }
    plaintext = json.dumps(
        envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return _get_cipher().encrypt(plaintext).decode("ascii")


def decrypt_field(student_id: int, field_name: str, encrypted: str) -> str:
    """Authenticate a token and ensure it belongs to the requested field/user.

    Key problems raise PrivateFieldConfigurationError. All ciphertext,
    envelope and context mismatches raise PrivateFieldDecryptionError.
    Do not include plaintext or tokens in exception/log messages.
    """
    _validate_context(student_id, field_name)
    if (
        not isinstance(encrypted, str)
        or not encrypted
        or len(encrypted) > _MAX_TOKEN_LENGTH
    ):
        raise PrivateFieldDecryptionError("Private-field decryption failed")

    cipher = _get_cipher()
    try:
        plaintext = cipher.decrypt(encrypted.encode("ascii"))
        envelope = json.loads(plaintext.decode("utf-8"))
        if not isinstance(envelope, dict) or set(envelope) != {
            "version", "student_id", "field", "value"
        }:
            raise ValueError("Invalid envelope")
        if type(envelope["version"]) is not int or envelope["version"] != _ENVELOPE_VERSION:
            raise ValueError("Invalid envelope version")
        if type(envelope["student_id"]) is not int or envelope["student_id"] != student_id:
            raise ValueError("Student mismatch")
        if envelope["field"] != field_name:
            raise ValueError("Field mismatch")
        return validate_private_value(field_name, envelope["value"])
    except (InvalidToken, UnicodeError, ValueError, TypeError, KeyError) as exc:
        raise PrivateFieldDecryptionError("Private-field decryption failed") from exc
