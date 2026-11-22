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

if __name__ == '__main__':
    unittest.main()
