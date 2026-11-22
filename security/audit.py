"""Validated audit event model; persistence is added in checkpoint 2."""
import json
from datetime import datetime, timezone

OUTCOMES = {
    'password_success': {'success'}, 'login_success': {'success'},
    'login_failure': {'failure'}, 'mfa_success': {'success'},
    'mfa_failure': {'failure'}, 'account_lockout': {'denied'},
    'access_denied': {'denied'}, 'grade_update': {'success', 'denied'},
    'suspicious_auth': {'failure', 'denied'},
}
METADATA = {
    'reason': {'invalid_credentials', 'invalid_code', 'replay', 'locked',
               'not_assigned', 'wrong_role', 'not_owner', 'mfa_required'},
    'method': {'password', 'password_mfa'},
    'stage': {'password', 'mfa'},
}

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False)

def build_event(event_type, *, actor_id=None, target_type, target_id=None,
                outcome, metadata=None):
    if not isinstance(event_type, str) or event_type not in OUTCOMES:
        raise ValueError('Invalid event type')
    if not isinstance(outcome, str) or outcome not in OUTCOMES[event_type]:
        raise ValueError('Invalid outcome')
    if target_type not in ('account', 'grade', 'course', 'resource'):
        raise ValueError('Invalid target type')
    for identifier in (actor_id, target_id):
        if identifier is not None and (type(identifier) is not int or
                                      not 0 < identifier <= 2**63-1):
            raise ValueError('Invalid identifier')
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise ValueError('Invalid metadata')
    for key, value in metadata.items():
        if key not in METADATA or not isinstance(value, str) or value not in METADATA[key]:
            raise ValueError('Disallowed metadata')
    return dict(timestamp_utc=datetime.now(timezone.utc).isoformat(timespec='microseconds'),
                event_type=event_type, actor_id=actor_id, target_type=target_type,
                target_id=target_id, outcome=outcome, metadata_json=canonical_json(metadata))
