import sqlite3
import unittest
from pathlib import Path
from security.audit import build_event, canonical_json

class AuditModelTests(unittest.TestCase):
    def test_event(self):
        event = build_event('login_failure', target_type='account', outcome='failure', metadata={'reason':'invalid_credentials'})
        self.assertIsNone(event['actor_id'])
        self.assertEqual(event['metadata_json'], '{"reason":"invalid_credentials"}')
        self.assertTrue(event['timestamp_utc'].endswith('+00:00'))

    def test_canonical(self):
        self.assertEqual(canonical_json({'b':2,'a':1}), canonical_json({'a':1,'b':2}))

    def test_reject_malformed(self):
        base = dict(event_type='login_failure', target_type='account', outcome='failure')
        for override in ({'event_type':'unknown'}, {'outcome':'success'}, {'actor_id':True}, {'target_id':-1}, {'metadata':{'password':'secret'}}, {'metadata':{'reason':'123456'}}, {'target_type':'unknown'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                build_event(**(base | override))

    def test_idempotent_migration(self):
        sql = (Path(__file__).resolve().parents[1] / 'migrations' / 'abdullah_audit_schema.sql').read_text()
        with sqlite3.connect(':memory:') as conn:
            conn.executescript(sql)
            conn.executescript(sql)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0], 0)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute('INSERT INTO audit_events(sequence) VALUES (?)', (1,))


from tempfile import TemporaryDirectory
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import patch
from security.audit import (AuditIntegrityError, GENESIS, initialize_schema,
                            load_key, log_event, verify_chain)


class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / 'audit.db'
        self.key = bytes(range(32))  # synthetic test key only
        initialize_schema(self.database)

    def append(self):
        return log_event(self.database, key=self.key, event_type='login_failure',
                         target_type='account', target_id=1, outcome='failure')

    def verify(self):
        return verify_chain(self.database, key=self.key)

    def alter(self, sql, args=()):
        with closing(sqlite3.connect(self.database)) as conn:
            with conn:
                conn.execute(sql, args)

    def test_empty_chain(self):
        self.assertEqual(self.verify().sequence, 0)
        self.assertEqual(self.verify().event_hmac, GENESIS)

    def test_sequential_append(self):
        first = self.append()
        second = self.append()
        self.assertEqual((first.sequence, second.sequence), (1, 2))
        self.assertNotEqual(first.event_hmac, second.event_hmac)
        self.assertEqual(self.verify(), second)
        with closing(sqlite3.connect(self.database)) as conn:
            self.assertEqual(conn.execute('SELECT previous_hmac FROM audit_events WHERE sequence=2').fetchone()[0], first.event_hmac)

    def test_content_modification(self):
        self.append()
        self.alter('UPDATE audit_events SET target_id=9 WHERE sequence=1')
        with self.assertRaises(AuditIntegrityError):
            self.verify()
        with self.assertRaises(AuditIntegrityError):
            self.append()

    def test_middle_deletion(self):
        for _ in range(3):
            self.append()
        self.alter('DELETE FROM audit_events WHERE sequence=2')
        with self.assertRaises(AuditIntegrityError):
            self.verify()

    def test_wrong_key(self):
        self.append()
        with self.assertRaises(AuditIntegrityError):
            verify_chain(self.database, key=b'x'*32)

    def test_broken_link(self):
        self.append()
        self.append()
        self.alter('UPDATE audit_events SET previous_hmac=? WHERE sequence=2', (GENESIS,))
        with self.assertRaises(AuditIntegrityError):
            self.verify()

    def test_tail_truncation_limitation(self):
        first = self.append()
        self.append()
        self.alter('DELETE FROM audit_events WHERE sequence=2')
        self.assertEqual(self.verify(), first)  # checkpoint 3 must detect this

    def test_concurrent_writes(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.append(), range(16)))
        self.assertEqual(sorted(r.sequence for r in results), list(range(1, 17)))
        self.assertEqual(self.verify().sequence, 16)

    def test_invalid_event_not_written(self):
        with self.assertRaises(ValueError):
            log_event(self.database, key=self.key, event_type='login_failure',
                      target_type='account', outcome='success')
        self.assertEqual(self.verify().sequence, 0)

    def test_environment_key(self):
        with patch.dict('os.environ', {'CAMPUSSHIELD_AUDIT_KEY': self.key.hex()}):
            self.assertEqual(load_key(), self.key)
        with patch.dict('os.environ', {'CAMPUSSHIELD_AUDIT_KEY': ''}):
            with self.assertRaises(ValueError):
                load_key()


if __name__ == '__main__':
    unittest.main()
