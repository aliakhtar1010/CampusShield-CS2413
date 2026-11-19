
import argparse
import getpass

from db import get_connection
from security.passwords import hash_password, verify_password


def activate_account(username: str) -> bool:
    conn = get_connection()

    try:
        user = conn.execute("""
            SELECT id, username, role, is_active
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if user is None:
            print("Account not found.")
            return False

        if user["is_active"]:
            print("Account is already active.")
            return False

        print(f"Account: {user['username']}")
        print(f"Role: {user['role']}")

        password = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm password: ")

        if password != confirmation:
            print("Passwords do not match.")
            return False

        try:
            password_hash = hash_password(password)
        except (ValueError, TypeError) as error:
            print(f"Activation failed: {error}")
            return False

        # Update only an inactive account to prevent
        # accidental overwriting of active credentials.
        cursor = conn.execute("""
            UPDATE users
            SET password_hash = ?, is_active = 1
            WHERE id = ? AND is_active = 0
        """, (password_hash, user["id"]))

        if cursor.rowcount != 1:
            conn.rollback()
            print("Account activation was not completed.")
            return False

        conn.commit()

        # Read the stored value to verify provisioning.
        stored = conn.execute("""
            SELECT password_hash, is_active
            FROM users
            WHERE id = ?
        """, (user["id"],)).fetchone()

        if (
            stored["is_active"] != 1
            or not verify_password(
                stored["password_hash"], password
            )
        ):
            print("Post-activation verification failed.")
            return False

        print("Account activated successfully.")
        print("Password stored using Argon2id.")
        return True

    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Activate a fictional CampusShield account"
    )
    parser.add_argument(
        "username",
        help="Existing fictional account username"
    )

    args = parser.parse_args()
    success = activate_account(args.username)

    raise SystemExit(0 if success else 1)
