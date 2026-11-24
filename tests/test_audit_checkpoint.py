import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from security.audit import AuditIntegrityError, verify_chain
from security.audit_checkpoint import ProtectedAudit


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        trusted = root / 'trusted'
        trusted.mkdir()
        self.database = root / 'audit.db'
        self.path = trusted / 'head.json'
        self.key = bytes(range(32))
        self.audit = ProtectedAudit(self.database, self.path, key=self.key)
        self.audit.initialize()

    def append(self):
        return self.audit.log_event(event_type='login_failure', target_type='account',
                                    target_id=1, outcome='failure')

    def alter(self, sql):
        with closing(sqlite3.connect(self.database)) as conn:
            with conn:
                conn.execute(sql)

    def test_valid(self):
        self.assertEqual(self.audit.verify().sequence, 0)
        self.assertEqual(self.append().sequence, 1)
        self.assertEqual(self.audit.verify().sequence, 1)

    def test_tail_truncation(self):
        self.append(); self.append()
        self.alter('DELETE FROM audit_events WHERE sequence=2')
        self.assertEqual(verify_chain(self.database, key=self.key).sequence, 1)
        with self.assertRaises(AuditIntegrityError): self.audit.verify()
        with self.assertRaises(AuditIntegrityError): self.append()

    def test_all_deleted(self):
        self.append()
        self.alter('DELETE FROM audit_events')
        with self.assertRaises(AuditIntegrityError): self.audit.verify()

    def test_missing_checkpoint(self):
        self.append(); self.path.unlink()
        with self.assertRaises(AuditIntegrityError): self.audit.verify()
        with self.assertRaises(AuditIntegrityError): self.append()
        with self.assertRaises(AuditIntegrityError): self.audit.initialize()

    def test_modified_checkpoint(self):
        data = json.loads(self.path.read_text())
        data['payload']['sequence'] = 1
        self.path.write_text(json.dumps(data))
        with self.assertRaises(AuditIntegrityError): self.audit.verify()

    def test_wrong_key_empty(self):
        with self.assertRaises(AuditIntegrityError):
            ProtectedAudit(self.database, self.path, key=b'x'*32).verify()

    def test_concurrent_writes(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.append(), range(16)))
        self.assertEqual(sorted(r.sequence for r in results), list(range(1,17)))
        self.assertEqual(self.audit.verify().sequence, 16)

    def test_interrupted_after_checkpoint(self):
        original = self.audit._write
        def interrupted(state):
            original(state)
            raise OSError('simulated interruption before database commit')
        with patch.object(self.audit, '_write', side_effect=interrupted):
            with self.assertRaises(AuditIntegrityError): self.append()
        self.assertEqual(verify_chain(self.database, key=self.key).sequence, 0)
        with self.assertRaises(AuditIntegrityError): self.audit.verify()

    def test_no_reset(self):
        with self.assertRaises(AuditIntegrityError): self.audit.initialize()

    def test_missing_database(self):
        self.database.unlink()
        with self.assertRaises(AuditIntegrityError): self.audit.verify()

    def test_checkpoint_write_failure_before_replace(self):
        with patch.object(self.audit, '_write', side_effect=OSError('disk failure')):
            with self.assertRaises(AuditIntegrityError): self.append()
        self.assertEqual(self.audit.verify().sequence, 0)
