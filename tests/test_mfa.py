
import pyotp

from security.mfa import (
    generate_mfa_secret,
    generate_provisioning_uri,
    verify_mfa_code
)


TEST_TIME = 1800000000


def test_unique_secrets():
    first = generate_mfa_secret()
    second = generate_mfa_secret()

    assert first != second


def test_valid_totp():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)

    code = totp.at(TEST_TIME)

    result = verify_mfa_code(
        secret,
        code,
        now=TEST_TIME
    )

    assert result == TEST_TIME // 30


def test_wrong_totp():
    secret = generate_mfa_secret()

    result = verify_mfa_code(
        secret,
        "not123",
        now=TEST_TIME
    )

    assert result is None


def test_expired_totp():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)

    old_code = totp.at(TEST_TIME - 120)

    result = verify_mfa_code(
        secret,
        old_code,
        now=TEST_TIME
    )

    assert result is None


def test_replay_prevention():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)

    code = totp.at(TEST_TIME)

    first_result = verify_mfa_code(
        secret,
        code,
        now=TEST_TIME
    )

    assert first_result is not None

    second_result = verify_mfa_code(
        secret,
        code,
        last_used_step=first_result,
        now=TEST_TIME
    )

    assert second_result is None


def test_clock_drift():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)

    earlier_code = totp.at(TEST_TIME - 30)

    result = verify_mfa_code(
        secret,
        earlier_code,
        now=TEST_TIME
    )

    assert result == (TEST_TIME // 30) - 1


def test_invalid_code_length():
    secret = generate_mfa_secret()

    assert verify_mfa_code(
        secret,
        "123",
        now=TEST_TIME
    ) is None


def test_invalid_secret():
    assert verify_mfa_code(
        "invalid-secret!",
        "123456",
        now=TEST_TIME
    ) is None


def test_provisioning_uri():
    secret = generate_mfa_secret()

    uri = generate_provisioning_uri(
        "instructor01",
        secret
    )

    assert uri.startswith("otpauth://totp/")
    assert "CampusShield" in uri
    assert "instructor01" in uri


def test_no_reuse_in_later_step():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)

    previous_step = TEST_TIME // 30
    old_code = totp.at(TEST_TIME)

    result = verify_mfa_code(
        secret,
        old_code,
        last_used_step=previous_step,
        now=TEST_TIME + 30
    )

    assert result is None
