
"""Application integration for CampusShield's protected audit log."""

import os
from pathlib import Path

from security.audit_checkpoint import ProtectedAudit


def audit_enabled():
    """Check whether protected audit logging is configured."""
    return bool(os.environ.get("CAMPUSSHIELD_AUDIT_KEY"))


def get_protected_audit():
    """Access the existing audit database and trusted checkpoint."""
    root = Path.home()

    return ProtectedAudit(
        root / "CampusShield-Secrets" / "audit.db",
        root / "CampusShield-Secrets-Trusted" / "checkpoint.json",
    )


def record_security_event(
    event_type,
    *,
    actor_id=None,
    target_type="account",
    target_id=None,
    outcome,
    metadata=None,
):
    """Record a validated, tamper-evident security event.

    Audit failures are propagated rather than silently ignored.
    Never store passwords, MFA codes, or sensitive personal data.
    """
    if not audit_enabled():
        return None

    audit = get_protected_audit()

    return audit.log_event(
        event_type=event_type,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        metadata=metadata or {},
    )
