from collections.abc import Callable

from flask import Flask, request


def create_unthrottled_baseline_app(
    username: str,
    password_hash: str,
    verify_password: Callable[[str, str], bool]
) -> Flask:
    """Create a test-client-only login baseline without throttling."""
    baseline_app = Flask("campusshield_unthrottled_baseline")
    baseline_app.config["TESTING"] = True

    @baseline_app.post("/login")
    def login():
        candidate_username = request.form.get(
            "username", ""
        ).strip().lower()
        candidate_password = request.form.get(
            "password", ""
        )

        if (
            candidate_username == username
            and verify_password(
                password_hash,
                candidate_password
            )
        ):
            return "Authenticated", 200

        return "Invalid credentials", 401

    return baseline_app
