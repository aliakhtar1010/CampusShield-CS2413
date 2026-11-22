"""Rule-based monitoring over a verified, consistent audit snapshot."""
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta

from .audit import AuditIntegrityError


@dataclass(frozen=True)
class WindowRule:
    threshold: int
    seconds: int

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in (self.threshold, self.seconds)):
            raise ValueError('Threshold and window must be positive integers')


@dataclass(frozen=True)
class MonitoringConfig:
    login: WindowRule = WindowRule(5, 300)
    mfa: WindowRule = WindowRule(3, 300)
    denial: WindowRule = WindowRule(3, 300)
    grade: WindowRule = WindowRule(10, 60)


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    timestamp_utc: str
    explanation: str
    subject_type: str
    subject_id: int | None
    sequence: int | None
    count: int

    def to_dict(self):
        return asdict(self)


def _time(value):
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return dt.astimezone(timezone.utc)


def scan(audit, config=MonitoringConfig()):
    """Return historical alerts, not a persistent notification queue.

    Verify and read within ONE protected transaction to avoid a verify/read race.
    On integrity or storage failure, return only a critical alert. Never trust
    unverified event fields or include exception text in alerts.
    """
    try:
        with audit._transaction() as conn:
            audit._verified(conn)
            rows = list(conn.execute('''SELECT sequence, timestamp_utc, event_type,
                actor_id, target_type, target_id, outcome FROM audit_events'''))
            timeline = sorted(((_time(r['timestamp_utc']), r['sequence'], r)
                               for r in rows), key=lambda item: item[:2])
    except (AuditIntegrityError, ValueError, TypeError, OverflowError):
        return [Alert('audit_integrity_failure', 'critical',
                      datetime.now(timezone.utc).isoformat(),
                      'Audit history could not be verified; investigate storage and checkpoint.',
                      'system', None, None, 1)]

    alerts = []
    windows = defaultdict(deque)
    def emit(rule, severity, explanation, subject, seq, dt, count=1):
        alerts.append(Alert(rule, severity, dt.isoformat(), explanation,
                            subject[0], subject[1], seq, count))

    def window(rule, severity, explanation, subject, seq, dt, setting):
        history = windows[(rule, subject)]
        cutoff = dt - timedelta(seconds=setting.seconds)
        while history and history[0] < cutoff:
            history.popleft()
        history.append(dt)
        # One alert per threshold crossing, not one per subsequent event.
        if len(history) == setting.threshold:
            emit(rule, severity, explanation, subject, seq, dt, len(history))

    for dt, seq, row in timeline:
        kind, outcome = row['event_type'], row['outcome']
        actor, target = row['actor_id'], row['target_id']
        account = ('account', target if row['target_type'] == 'account' and target is not None else actor)
        # Unknown accounts are aggregated explicitly, not attributed to a person.
        if account[1] is None:
            account = ('unknown_account', None)
        subject = ('actor', actor) if actor is not None else ('unknown_actor', None)
        if kind == 'login_failure':
            window('repeated_login_failures', 'high', 'Repeated failed logins within configured window.', account, seq, dt, config.login)
        elif kind == 'mfa_failure':
            window('repeated_mfa_failures', 'high', 'Repeated MFA failures within configured window.', account, seq, dt, config.mfa)
        elif kind == 'account_lockout':
            emit('account_lockout', 'high', 'Temporary account lockout recorded.', account, seq, dt)
        elif kind == 'suspicious_auth':
            emit('suspicious_auth', 'medium', 'Suspicious authentication event recorded.', account, seq, dt)
        if kind == 'access_denied' or (kind == 'grade_update' and outcome == 'denied'):
            window('repeated_authorization_denials', 'medium', 'Repeated authorization denials within configured window.', subject, seq, dt, config.denial)
        if kind == 'grade_update':
            if outcome == 'denied':
                emit('unauthorized_grade_update', 'high', 'Grade update denied by authorization controls.', subject, seq, dt)
            elif outcome == 'success':
                window('frequent_grade_updates', 'medium', 'High frequency of authorized grade updates.', subject, seq, dt, config.grade)
    return alerts
