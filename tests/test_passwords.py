
import pytest

from security.passwords import (
    hash_password,
    verify_password,
    needs_rehash,
    validate_password
)


def test_valid_password():
    password = "CampusShield2026!"
    password_hash = hash_password(password)

    assert password_hash.startswith("$argon2id$")
    assert verify_password(password_hash, password)


def test_wrong_password():
    password_hash = hash_password("CorrectPassword2026!")

    assert not verify_password(
        password_hash,
        "IncorrectPassword2026!"
    )


def test_unique_random_salts():
    password = "IdenticalPassword2026!"

    hash_one = hash_password(password)
    hash_two = hash_password(password)

    assert hash_one != hash_two
    assert verify_password(hash_one, password)
    assert verify_password(hash_two, password)


def test_short_password():
    with pytest.raises(ValueError):
        hash_password("123456")


def test_oversized_password():
    with pytest.raises(ValueError):
        hash_password("A" * 1025)


def test_invalid_hash():
    assert not verify_password(
        "!NOT_ACTIVATED",
        "CampusShield2026!"
    )


def test_plaintext_not_stored():
    password = "CampusShield2026!"
    password_hash = hash_password(password)

    assert password not in password_hash


def test_hash_upgrade_not_needed():
    password_hash = hash_password("CampusShield2026!")

    assert needs_rehash(password_hash) is False


def test_invalid_hash_requires_replacement():
    assert needs_rehash("invalid-hash") is True


def test_password_validation():
    validate_password("ValidPassword2026!")

    with pytest.raises(TypeError):
        validate_password(12345678)
