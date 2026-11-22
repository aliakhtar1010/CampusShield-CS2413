"""Validated security events and transaction-safe HMAC audit chain."""
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

import hashlib
import hmac
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from dataclasses import dataclass

GENESIS = '0' * 64
FIELDS = ('timestamp_utc', 'event_type', 'actor_id', 'target_type',
          'target_id', 'outcome', 'metadata_json')


class AuditIntegrityError(RuntimeError):
    """Audit history cannot be trusted."""


@dataclass(frozen=True)
class ChainState:
    sequence: int
    event_hmac: str


def load_key():
    """Require a dedicated 32-byte key encoded as 64 hexadecimal characters."""
    raw = os.environ.get('CAMPUSSHIELD_AUDIT_KEY', '')
    if len(raw) != 64 or any(c not in '0123456789abcdefABCDEF' for c in raw):
        raise ValueError('CAMPUSSHIELD_AUDIT_KEY must be 64 hex characters')
    return bytes.fromhex(raw)


def _key(key):
    key = load_key() if key is None else key
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('Audit key must be 32 bytes')
    return key


def _connect(database):
    conn = sqlite3.connect(database, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_schema(database):
    """Apply the owned migration explicitly; never reset existing events."""
    migration = Path(__file__).resolve().parents[1] / 'migrations' / 'abdullah_audit_schema.sql'
    with closing(_connect(database)) as conn:
        conn.executescript(migration.read_text(encoding='utf-8'))


def _authenticator(key, sequence, previous, event):
    payload = canonical_json(dict(version=1, sequence=sequence,
                                  previous_hmac=previous, **event))
    return hmac.new(key, b'CampusShield/audit/event/v1\x00' + payload.encode('utf-8'),
                    hashlib.sha256).hexdigest()


def _verify_connection(conn, key):
    state = ChainState(0, GENESIS)
    for row in conn.execute('SELECT * FROM audit_events ORDER BY sequence'):
        seq = state.sequence + 1
        if row['sequence'] != seq or row['previous_hmac'] != state.event_hmac:
            raise AuditIntegrityError(f'Broken chain at sequence {seq}')
        event = {field: row[field] for field in FIELDS}
        expected = _authenticator(key, seq, state.event_hmac, event)
        actual = row['event_hmac']
        if not isinstance(actual, str) or not actual.isascii() or not hmac.compare_digest(expected, actual):
            raise AuditIntegrityError(f'HMAC mismatch at sequence {seq}')
        state = ChainState(seq, expected)
    return state


def verify_chain(database, *, key=None):
    """Verify a consistent snapshot. Does not detect valid suffix truncation yet."""
    key = _key(key)
    with closing(_connect(database)) as conn:
        conn.execute('BEGIN')
        return _verify_connection(conn, key)


def log_event(database, *, key=None, **event_fields):
    """Validate, verify existing history and append under one SQLite write lock.

    Call outside any outstanding application write transaction. A full scan
    per append is intentional for this small teaching project.
    """
    key = _key(key)
    # Validate before taking a database lock; timestamp is assigned in lock order.
    event = build_event(**event_fields)
    with closing(_connect(database)) as conn:
        conn.execute('BEGIN IMMEDIATE')
        try:
            state = _verify_connection(conn, key)
            event['timestamp_utc'] = datetime.now(timezone.utc).isoformat(timespec='microseconds')
            seq = state.sequence + 1
            digest = _authenticator(key, seq, state.event_hmac, event)
            conn.execute('''INSERT INTO audit_events
                (sequence, timestamp_utc, event_type, actor_id, target_type,
                 target_id, outcome, metadata_json, previous_hmac, event_hmac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (seq, *(event[field] for field in FIELDS), state.event_hmac, digest))
            conn.commit()
            return ChainState(seq, digest)
        except BaseException:
            conn.rollback()
            raise
