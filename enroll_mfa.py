
import argparse
import getpass

from db import get_connection
from security.encryption import encrypt_secret
from security.mfa import (
    generate_mfa_secret,
    generate_provisioning_uri,
    verify_mfa_code
)

PRIVILEGED_ROLES = {"instructor", "security_admin"}


def enroll_mfa(username: str) -> bool:
    conn = get_connection()

    try:
        user = conn.execute("""
            SELECT id, username, role, is_active
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if user is None or not user["is_active"]:
            print("Account not found or inactive.")
            return False

        if user["role"] not in PRIVILEGED_ROLES:
            print("MFA enrollment is for privileged accounts.")
            return False

        existing = conn.execute("""
            SELECT user_id
            FROM mfa_credentials
            WHERE user_id = ?
        """, (user["id"],)).fetchone()

        if existing:
            print("MFA credentials already exist.")
            return False

        secret = generate_mfa_secret()
        uri = generate_provisioning_uri(username, secret)

        print("\nMFA enrollment for:", username)
        print("Open your authenticator app.")
        print("Add an account using this provisioning URI:")
        print(uri)
        print("\nKeep this URI private.")

        code = getpass.getpass(
            "Enter the current 6-digit code: "
        )

        matched_step = verify_mfa_code(secret, code)

        if matched_step is None:
            print("Invalid code. Enrollment cancelled.")
            return False

        encrypted_secret = encrypt_secret(secret)

        conn.execute("""
            INSERT INTO mfa_credentials (
                user_id,
                encrypted_secret,
                last_used_step,
                is_enabled
            )
            VALUES (?, ?, ?, 1)
        """, (
            user["id"],
            encrypted_secret,
            matched_step
        ))

        conn.commit()

        print("MFA enrollment completed successfully.")
        return True

    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enroll a privileged CampusShield account in MFA"
    )
    parser.add_argument("username")

    args = parser.parse_args()

    success = enroll_mfa(args.username)
    raise SystemExit(0 if success else 1)
