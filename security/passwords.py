
from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError
)

# Argon2id configuration
# Memory cost is measured in KiB.
PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 1024


def validate_password(password: str) -> None:
    """Validate a new password before hashing."""

    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            "Password must contain at least 12 characters"
        )

    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError("Password is too long")


def hash_password(password: str) -> str:
    """Hash a password with Argon2id and a random salt."""

    validate_password(password)
    return PASSWORD_HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify credentials without exposing the stored password."""

    if not isinstance(stored_hash, str):
        return False

    if not isinstance(password, str):
        return False

    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False

    try:
        return PASSWORD_HASHER.verify(
            stored_hash,
            password
        )

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError
    ):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Check whether stored hashing parameters are outdated."""

    try:
        return PASSWORD_HASHER.check_needs_rehash(stored_hash)
    except (VerificationError, InvalidHashError, ValueError):
        return True
