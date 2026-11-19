
import time
import pyotp


ISSUER = "CampusShield"
TOTP_INTERVAL = 30
TOTP_DIGITS = 6


def generate_mfa_secret() -> str:
    """Generate a unique MFA enrollment secret."""
    return pyotp.random_base32()


def generate_provisioning_uri(
    username: str,
    secret: str
) -> str:
    """
    Generate an otpauth URI compatible with
    standard authenticator applications.
    """
    totp = pyotp.TOTP(
        secret,
        interval=TOTP_INTERVAL,
        digits=TOTP_DIGITS
    )

    return totp.provisioning_uri(
        name=username,
        issuer_name=ISSUER
    )


def verify_mfa_code(
    secret: str,
    code: str,
    last_used_step: int = -1,
    now: int | None = None
) -> int | None:
    """
    Verify a TOTP code.

    Returns the matched 30-second time step
    when verification succeeds.

    Returns None for an invalid or replayed code.

    last_used_step prevents accepting an OTP
    that has already been used.
    """

    if not isinstance(code, str):
        return None

    # Do not silently remove whitespace or
    # convert integers to strings.
    if len(code) != TOTP_DIGITS or not code.isascii():
        return None

    if not code.isdigit():
        return None

    if not isinstance(secret, str) or not secret:
        return None

    if not isinstance(last_used_step, int):
        return None

    timestamp = int(time.time()) if now is None else int(now)

    if timestamp < 0:
        return None

    current_step = timestamp // TOTP_INTERVAL

    try:
        totp = pyotp.TOTP(
            secret,
            interval=TOTP_INTERVAL,
            digits=TOTP_DIGITS
        )

        # Permit one time step of clock drift.
        # Earlier codes cannot be reused after
        # a later step has been accepted.
        for offset in (-1, 0, 1):
            candidate_step = current_step + offset

            if candidate_step <= last_used_step:
                continue

            if candidate_step < 0:
                continue

            candidate_time = (
                candidate_step * TOTP_INTERVAL
            )

            if totp.verify(
                code,
                for_time=candidate_time,
                valid_window=0
            ):
                return candidate_step

    except (ValueError, TypeError):
        return None

    return None
