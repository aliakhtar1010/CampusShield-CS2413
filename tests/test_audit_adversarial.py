"""Local synthetic attack experiments against the protected audit API."""
import json
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from security.audit import AuditIntegrityError, verify_chain
from security.audit_checkpoint import ProtectedAudit


class AdversarialAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'trusted').mkdir()
        self.db = root / 'audit.db'
        self.head = root / 'trusted' / 'head.json'
        self.key = bytes(range(32))
        self.audit = ProtectedAudit(self.db, self.head, key=self.key)
        self.audit.initialize()

    def append(self):
        return self.audit.log_event(event_type='grade_update', actor_id=4,
                                    target_type='grade', target_id=8,
                                    outcome='denied', metadata={'reason': 'not_assigned'})

    def sql(self, statement, args=()):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            return conn.execute(statement, args).fetchall()

    def assert_blocked(self):
        before = self.sql('SELECT * FROM audit_events ORDER BY sequence')
        checkpoint = self.head.read_bytes()
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify()
        with self.assertRaises(AuditIntegrityError):
            self.append()
        self.assertEqual(before, self.sql('SELECT * FROM audit_events ORDER BY sequence'))
        self.assertEqual(checkpoint, self.head.read_bytes())

    def test_forged_event(self):
        self.append()
        self.sql('''INSERT INTO audit_events SELECT 2, timestamp_utc, event_type,
                 actor_id, target_type, target_id, outcome, metadata_json,
                 event_hmac, ? FROM audit_events WHERE sequence=1''', ('f'*64,))
        self.assert_blocked()

    def test_outcome_rewrite(self):
        self.append()
        self.sql("UPDATE audit_events SET outcome='success'")
        self.assert_blocked()

    def test_metadata_rewrite(self):
        self.append()
        self.sql('UPDATE audit_events SET metadata_json=?', ('{}',))
        self.assert_blocked()

    def test_timestamp_rewrite(self):
        self.append()
        self.sql('UPDATE audit_events SET timestamp_utc=?', ('2000-01-01T00:00:00+00:00',))
        self.assert_blocked()

    def test_database_snapshot_rollback(self):
        self.append()
        snapshot = self.db.read_bytes()
        self.append()
        self.db.write_bytes(snapshot)
        self.assertEqual(verify_chain(self.db, key=self.key).sequence, 1)
        self.assert_blocked()

    def test_checkpoint_snapshot_rollback(self):
        self.append()
        snapshot = self.head.read_bytes()
        self.append()
        self.head.write_bytes(snapshot)
        self.assert_blocked()

    def test_malformed_checkpoints(self):
        self.append()
        for content in (b'{', b'[]', b'null', b'\xff', b'x'*16385,
                        b'{"payload":{},"tag":"bad"}'):
            with self.subTest(content=content[:20]):
                self.head.write_bytes(content)
                self.assert_blocked()

    def test_cross_database_checkpoint_replay(self):
        self.append()
        other = self.db.with_name('other.db')
        other.write_bytes(self.db.read_bytes())
        with self.assertRaises(AuditIntegrityError):
            ProtectedAudit(other, self.head, key=self.key).verify()

    def test_coordinated_rollback_known_limitation(self):
        # Both trusted and untrusted storage rolled back: outside threat model.
        self.append()
        db_snapshot = self.db.read_bytes()
        checkpoint_snapshot = self.head.read_bytes()
        self.append()
        self.db.write_bytes(db_snapshot)
        self.head.write_bytes(checkpoint_snapshot)
        self.assertEqual(self.audit.verify().sequence, 1)
