import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from security.audit_checkpoint import ProtectedAudit
from security.monitor import scan, WindowRule, MonitoringConfig


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'trusted').mkdir()
        self.db = root / 'audit.db'
        self.audit = ProtectedAudit(self.db, root / 'trusted' / 'head.json', key=b't'*32)
        self.audit.initialize()
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def event(self, kind='login_failure', outcome='failure', actor=None, target=1,
              target_type='account', seconds=0):
        with patch('security.audit.datetime') as clock:
            clock.now.return_value = self.start + timedelta(seconds=seconds)
            return self.audit.log_event(event_type=kind, outcome=outcome,
                                        actor_id=actor, target_id=target, target_type=target_type)

    def rules(self, config=MonitoringConfig()):
        return [a.rule for a in scan(self.audit, config)]

    def test_login_threshold(self):
        for i in range(4): self.event(seconds=i)
        self.assertEqual(self.rules(), [])
        self.event(seconds=4)
        self.event(seconds=5)
        alerts = scan(self.audit)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].rule, alerts[0].count, alerts[0].subject_id), ('repeated_login_failures', 5, 1))

    def test_mfa(self):
        for i in range(3): self.event('mfa_failure', seconds=i)
        self.assertEqual(self.rules(), ['repeated_mfa_failures'])

    def test_denial(self):
        for i in range(3): self.event('access_denied', 'denied', actor=4, seconds=i)
        self.assertEqual(self.rules(), ['repeated_authorization_denials'])

    def test_grade_denied(self):
        self.event('grade_update', 'denied', actor=4, target_type='grade')
        self.assertEqual(self.rules(), ['unauthorized_grade_update'])

    def test_grade_frequency(self):
        for i in range(10): self.event('grade_update', 'success', actor=4, target_type='grade', seconds=i)
        self.assertEqual(self.rules(), ['frequent_grade_updates'])

    def test_lockout(self):
        self.event('account_lockout', 'denied')
        self.assertEqual(self.rules(), ['account_lockout'])

    def test_integrity_failure(self):
        self.event()
        with closing(sqlite3.connect(self.db)) as conn:
            with conn: conn.execute('DELETE FROM audit_events')
        alerts = scan(self.audit)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].rule, alerts[0].severity), ('audit_integrity_failure', 'critical'))

    def test_normal_activity(self):
        for i in range(12):
            self.event('login_success', 'success', actor=1, seconds=i)
            self.event('grade_update', 'success', actor=4, target_type='grade', seconds=i*90)
        self.assertEqual(self.rules(), [])

    def test_distinct_accounts(self):
        for i in range(8): self.event(target=i % 2 + 1, seconds=i)
        self.assertEqual(self.rules(), [])

    def test_window_expiration(self):
        for i in range(5): self.event(seconds=i*301)
        self.assertEqual(self.rules(), [])

    def test_configurable_threshold(self):
        self.event(); self.event(seconds=10)
        config = MonitoringConfig(login=WindowRule(2, 30))
        self.assertEqual(self.rules(config), ['repeated_login_failures'])
        with self.assertRaises(ValueError): WindowRule(0, 30)

    def test_unknown_account_aggregation(self):
        for i in range(5): self.event(target=None, seconds=i)
        alert = scan(self.audit)[0]
        self.assertEqual((alert.subject_type, alert.subject_id), ('unknown_account', None))
        self.assertNotIn('metadata_json', alert.to_dict())

    def test_threshold_rearms(self):
        for base in (0, 400):
            for i in range(5): self.event(seconds=base+i)
        self.assertEqual(self.rules(), ['repeated_login_failures']*2)

    def test_suspicious_auth(self):
        self.event('suspicious_auth')
        self.assertEqual(self.rules(), ['suspicious_auth'])
