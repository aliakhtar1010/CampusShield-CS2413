
import pytest

from cryptography.fernet import Fernet

from security.encryption import (
    encrypt_secret,
    decrypt_secret
)


@pytest.fixture(autouse=True)
def encryption_key(monkeypatch):
    """
    Give each test a separate temporary key.
    """
    key = Fernet.generate_key().decode()

    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY",
        key
    )


def test_encrypt_and_decrypt():
    secret = "TESTMFASECRET123456"

    encrypted = encrypt_secret(secret)

    assert encrypted != secret
    assert decrypt_secret(encrypted) == secret


def test_randomized_encryption():
    secret = "TESTMFASECRET123456"

    first = encrypt_secret(secret)
    second = encrypt_secret(secret)

    assert first != second


def test_modified_ciphertext_rejected():
    encrypted = encrypt_secret(
        "TESTMFASECRET123456"
    )

    # Corrupt the ciphertext before its MAC.
    modified = (
        encrypted[:20]
        + ("A" if encrypted[20] != "A" else "B")
        + encrypted[21:]
    )

    with pytest.raises(ValueError):
        decrypt_secret(modified)


def test_wrong_key_rejected(monkeypatch):
    encrypted = encrypt_secret(
        "TESTMFASECRET123456"
    )

    different_key = Fernet.generate_key().decode()

    monkeypatch.setenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY",
        different_key
    )

    with pytest.raises(ValueError):
        decrypt_secret(encrypted)


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        encrypt_secret("")


def test_missing_key_rejected(monkeypatch):
    monkeypatch.delenv(
        "CAMPUSSHIELD_ENCRYPTION_KEY",
        raising=False
    )

    with pytest.raises(RuntimeError):
        encrypt_secret("TESTMFASECRET123456")
