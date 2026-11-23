"""Phase 4A tests for contact field encryption; no persistent DB or keys."""

import json

import pytest
from cryptography.fernet import Fernet

from db_security.field_encryption import (
    PrivateFieldConfigurationError,
    PrivateFieldDecryptionError,
    decrypt_field,
    encrypt_field,
    validate_private_value,
)


@pytest.fixture(autouse=True)
def isolated_test_key(monkeypatch):
    """Each test gets a temporary Fernet key, never a developer's key."""
    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii")
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [("email", "student01@example.invalid"), ("phone", "+15065550123")],
)
def test_encrypt_decrypt_round_trip(field_name, value):
    token = encrypt_field(1, field_name, value)
    assert isinstance(token, str)
    assert token != value
    assert value not in token
    assert decrypt_field(1, field_name, token) == value


def test_fernet_encryption_is_randomized():
    first = encrypt_field(1, "email", "student01@example.invalid")
    second = encrypt_field(1, "email", "student01@example.invalid")
    assert first != second


def test_modified_ciphertext_is_rejected():
    token = encrypt_field(1, "email", "student01@example.invalid")
    last = "A" if token[-5] != "A" else "B"
    tampered = token[:-5] + last + token[-4:]
    with pytest.raises(PrivateFieldDecryptionError, match="decryption failed"):
        decrypt_field(1, "email", tampered)


def test_different_valid_key_is_rejected(monkeypatch):
    token = encrypt_field(1, "email", "student01@example.invalid")
    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii")
    )
    with pytest.raises(PrivateFieldDecryptionError):
        decrypt_field(1, "email", token)


@pytest.mark.parametrize("key_setting", [None, "not-a-valid-fernet-key"])
def test_missing_or_invalid_key_fails_closed(monkeypatch, key_setting):
    token = encrypt_field(1, "phone", "+15065550123")
    if key_setting is None:
        monkeypatch.delenv("CAMPUSSHIELD_ENCRYPTION_KEY")
    else:
        monkeypatch.setenv("CAMPUSSHIELD_ENCRYPTION_KEY", key_setting)
    with pytest.raises(PrivateFieldConfigurationError):
        encrypt_field(1, "email", "student01@example.invalid")
    with pytest.raises(PrivateFieldConfigurationError):
        decrypt_field(1, "phone", token)


def test_token_cannot_be_used_for_another_student():
    token = encrypt_field(1, "email", "student01@example.invalid")
    with pytest.raises(PrivateFieldDecryptionError):
        decrypt_field(2, "email", token)


def test_token_cannot_be_used_for_a_different_field():
    token = encrypt_field(1, "email", "student01@example.invalid")
    with pytest.raises(PrivateFieldDecryptionError):
        decrypt_field(1, "phone", token)


def test_valid_ciphertext_transplanted_across_students_is_rejected():
    student_one = encrypt_field(1, "phone", "+15065550123")
    student_two = encrypt_field(2, "phone", "+15065550124")
    assert decrypt_field(1, "phone", student_one) == "+15065550123"
    assert decrypt_field(2, "phone", student_two) == "+15065550124"
    with pytest.raises(PrivateFieldDecryptionError):
        decrypt_field(1, "phone", student_two)


@pytest.mark.parametrize("student_id", [0, -1, True, "1", 1.0, None])
def test_invalid_student_id_rejected(student_id):
    with pytest.raises(ValueError, match="student ID"):
        encrypt_field(student_id, "email", "student01@example.invalid")
    with pytest.raises(ValueError, match="student ID"):
        decrypt_field(student_id, "email", "invalid")


@pytest.mark.parametrize("field_name", [None, "", "role", "encrypted_email", "EMAIL", [], {}])
def test_unrecognized_field_rejected(field_name):
    with pytest.raises(ValueError, match="Unsupported private field"):
        encrypt_field(1, field_name, "student01@example.invalid")
    with pytest.raises(ValueError, match="Unsupported private field"):
        decrypt_field(1, field_name, "invalid")


@pytest.mark.parametrize(
    ("field_name", "bad_value"),
    [
        ("email", ""),
        ("email", "not-an-email"),
        ("email", "student@example.invalid' OR 1=1 --"),
        ("email", "student @example.invalid"),
        ("email", "student01@example.invalid "),
        ("email", "a" * 245 + "@example.invalid"),
        ("phone", "555-0100"),
        ("phone", "+1 506 555 0123"),
        ("phone", "+0000000000"),
        ("phone", "+12"),
        ("phone", None),
    ],
)
def test_invalid_private_values_rejected(field_name, bad_value):
    with pytest.raises(ValueError):
        validate_private_value(field_name, bad_value)
    with pytest.raises(ValueError):
        encrypt_field(1, field_name, bad_value)


@pytest.mark.parametrize("ciphertext", [None, "", b"encrypted", "random-text", "A" * 4097])
def test_invalid_ciphertexts_fail_closed(ciphertext):
    with pytest.raises(PrivateFieldDecryptionError):
        decrypt_field(1, "email", ciphertext)


@pytest.mark.parametrize(
    "envelope",
    [
        {"version": 99, "student_id": 1, "field": "email", "value": "student01@example.invalid"},
        {"version": 1, "student_id": 1, "field": "email"},
        {"version": 1, "student_id": 1, "field": "email", "value": "not-an-email"},
        {"version": 1, "student_id": "1", "field": "email", "value": "student01@example.invalid"},
    ],
)
def test_authenticated_but_invalid_envelopes_are_rejected(monkeypatch, envelope):
    """Even valid Fernet ciphertext must contain our expected structured data."""
    import os
    cipher = Fernet(os.environ["CAMPUSSHIELD_ENCRYPTION_KEY"].encode("ascii"))
    forged = cipher.encrypt(json.dumps(envelope).encode("utf-8")).decode("ascii")
    with pytest.raises(PrivateFieldDecryptionError):
        decrypt_field(1, "email", forged)
