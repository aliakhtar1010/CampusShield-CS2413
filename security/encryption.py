
import os

from cryptography.fernet import Fernet, InvalidToken


def get_cipher():
    """
    Load the encryption key from an environment variable.

    Keeping the key outside the database prevents
    someone with only database access from directly
    decrypting stored MFA secrets.
    """
    key = os.environ.get("CAMPUSSHIELD_ENCRYPTION_KEY")

    if not key:
        raise RuntimeError(
            "CAMPUSSHIELD_ENCRYPTION_KEY is not configured"
        )

    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            "Invalid encryption key configuration"
        ) from exc


def encrypt_secret(secret: str) -> str:
    """
    Encrypt a sensitive MFA secret using Fernet.
    """
    if not isinstance(secret, str) or not secret:
        raise ValueError("Invalid MFA secret")

    ciphertext = get_cipher().encrypt(
        secret.encode("utf-8")
    )

    return ciphertext.decode("ascii")


def decrypt_secret(encrypted: str) -> str:
    """
    Decrypt and authenticate a stored MFA secret.

    Modified ciphertext or an incorrect key
    causes decryption to fail.
    """
    if not isinstance(encrypted, str):
        raise ValueError("Invalid encrypted secret")

    try:
        plaintext = get_cipher().decrypt(
            encrypted.encode("ascii")
        )

        return plaintext.decode("utf-8")

    except (
        InvalidToken,
        ValueError,
        UnicodeError
    ) as exc:
        raise ValueError(
            "MFA secret decryption failed"
        ) from exc
