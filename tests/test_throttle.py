
import pytest

import db
from security.throttle import (
    get_auth_status,
    record_auth_failure,
    reset_auth_failures,
    MAX_FAILURES
)


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(
        db,
        "DB_PATH",
        tmp_path / "throttle_test.db"
    )
    db.init_db()


def test_initial_state():
    status = get_auth_status(
        "student01", "password", now=1000
    )

    assert status["blocked"] is False
    assert status["remaining"] == MAX_FAILURES


def test_failure_increments():
    status = record_auth_failure(
        "student01", "password", now=1000
    )

    assert status["failures"] == 1
    assert status["remaining"] == 4


def test_five_failures_trigger_lockout():
    for i in range(5):
        status = record_auth_failure(
            "student01", "password", now=1000 + i
        )

    assert status["blocked"] is True
    assert status["retry_after"] > 0


def test_lockout_persists():
    for i in range(5):
        record_auth_failure(
            "student01", "password", now=1000 + i
        )

    # Fresh database connection, same restriction.
    status = get_auth_status(
        "student01", "password", now=1100
    )

    assert status["blocked"] is True


def test_lockout_expires():
    for i in range(5):
        record_auth_failure(
            "student01", "password", now=1000 + i
        )

    status = get_auth_status(
        "student01", "password", now=1400
    )

    assert status["blocked"] is False
    assert status["remaining"] == 5


def test_window_expires():
    record_auth_failure(
        "student01", "password", now=1000
    )

    status = get_auth_status(
        "student01", "password", now=1301
    )

    assert status["failures"] == 0


def test_success_resets_failures():
    record_auth_failure(
        "student01", "password", now=1000
    )

    reset_auth_failures(
        "student01", "password"
    )

    status = get_auth_status(
        "student01", "password", now=1001
    )

    assert status["failures"] == 0


def test_mfa_counter_is_independent():
    record_auth_failure(
        "instructor01", "mfa", now=1000
    )

    password_status = get_auth_status(
        "instructor01", "password", now=1000
    )

    mfa_status = get_auth_status(
        "instructor01", "mfa", now=1000
    )

    assert password_status["failures"] == 0
    assert mfa_status["failures"] == 1


def test_usernames_are_normalized():
    record_auth_failure(
        " Student01 ", "password", now=1000
    )

    status = get_auth_status(
        "student01", "password", now=1000
    )

    assert status["failures"] == 1


def test_invalid_stage_rejected():
    with pytest.raises(ValueError):
        record_auth_failure(
            "student01", "invalid", now=1000
        )


def test_blocked_attempt_does_not_extend_lockout():
    for i in range(5):
        record_auth_failure(
            "student01", "password", now=1000 + i
        )

    before = get_auth_status(
        "student01", "password", now=1010
    )

    record_auth_failure(
        "student01", "password", now=1010
    )

    after = get_auth_status(
        "student01", "password", now=1010
    )

    assert after["retry_after"] == before["retry_after"]
