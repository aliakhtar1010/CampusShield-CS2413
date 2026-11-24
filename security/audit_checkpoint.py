"""Protected audit API. All writers must use the same external checkpoint."""
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path

from .audit import (AuditIntegrityError, ChainState, GENESIS, _key, _connect,
                    _verify_connection, _append_connection, build_event,
                    canonical_json, initialize_schema)


class ProtectedAudit:
    """SQLite's write lock serializes checkpoint reads and writes across processes.

    The checkpoint is replaced BEFORE committing SQLite. A crash in between
    leaves a mismatch, which must be investigated, never automatically repaired.
    The checkpoint directory must be trusted, local and outside the repository.
    """
    def __init__(self, database, checkpoint, *, key=None):
        self.database = Path(database).resolve()
        self.checkpoint = Path(checkpoint).resolve()
        if self.database == self.checkpoint or self.checkpoint.parent == self.database.parent:
            raise ValueError('Use a separate trusted checkpoint directory')
        self.key = _key(key)

    def _tag(self, payload):
        return hmac.new(self.key, b'CampusShield/audit/checkpoint/v1\x00' +
                        canonical_json(payload).encode('utf-8'), hashlib.sha256).hexdigest()

    def _payload(self, state):
        return dict(version=1, database=str(self.database), sequence=state.sequence,
                    event_hmac=state.event_hmac)

    def _read(self):
        try:
            with self.checkpoint.open('rb') as stream:
                raw = stream.read(16385)
            if len(raw) > 16384:
                raise ValueError('Oversize checkpoint')
            data = json.loads(raw)
            if type(data) is not dict or set(data) != {'payload', 'tag'}:
                raise ValueError('Invalid envelope')
            payload, tag = data['payload'], data['tag']
            if type(payload) is not dict or set(payload) != {'version', 'database', 'sequence', 'event_hmac'}:
                raise ValueError('Invalid payload')
            if (type(payload['version']) is not int or payload['version'] != 1 or
                payload['database'] != str(self.database) or
                type(payload['sequence']) is not int or not 0 <= payload['sequence'] <= 2**63-1 or
                not isinstance(payload['event_hmac'], str) or len(payload['event_hmac']) != 64 or
                any(c not in '0123456789abcdef' for c in payload['event_hmac']) or
                not isinstance(tag, str) or not tag.isascii() or
                not hmac.compare_digest(self._tag(payload), tag)):
                raise ValueError('Invalid checkpoint authentication or format')
            return ChainState(payload['sequence'], payload['event_hmac'])
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise AuditIntegrityError('Missing, unreadable or invalid checkpoint') from exc

    def _write(self, state):
        payload = self._payload(state)
        data = canonical_json(dict(payload=payload, tag=self._tag(payload))).encode('utf-8')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.checkpoint.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.checkpoint)
            if os.name == 'posix':
                fd = os.open(self.checkpoint.parent, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @contextmanager
    def _transaction(self):
        if not self.database.is_file():
            raise AuditIntegrityError('Audit database missing')
        try:
            with closing(_connect(self.database)) as conn:
                conn.execute('BEGIN IMMEDIATE')
                try:
                    yield conn
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise
        except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
            raise AuditIntegrityError('Audit storage operation failed') from exc

    def initialize(self):
        """Explicit one-time provisioning ONLY for a known fresh audit log."""
        if self.checkpoint.exists():
            raise AuditIntegrityError('Checkpoint already exists; refusing reset')
        initialize_schema(self.database)
        with self._transaction() as conn:
            if self.checkpoint.exists():
                raise AuditIntegrityError('Checkpoint already exists; refusing reset')
            state = _verify_connection(conn, self.key)
            if state != ChainState(0, GENESIS):
                raise AuditIntegrityError('Refusing to anchor existing history')
            self._write(state)
            return state

    def _verified(self, conn):
        expected = self._read()
        actual = _verify_connection(conn, self.key)
        if actual != expected:
            raise AuditIntegrityError('Database and checkpoint disagree')
        return actual

    def verify(self):
        with self._transaction() as conn:
            return self._verified(conn)

    def log_event(self, **event_fields):
        event = build_event(**event_fields)
        with self._transaction() as conn:
            state = self._verified(conn)
            result = _append_connection(conn, self.key, state, event)
            self._write(result)
            return result
