CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    timestamp_utc TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('password_success','login_success','login_failure','mfa_success','mfa_failure','account_lockout','access_denied','grade_update','suspicious_auth')),
    actor_id INTEGER CHECK (actor_id > 0),
    target_type TEXT NOT NULL CHECK (target_type IN ('account','grade','course','resource')),
    target_id INTEGER CHECK (target_id > 0),
    outcome TEXT NOT NULL CHECK (outcome IN ('success','failure','denied')),
    metadata_json TEXT NOT NULL,
    previous_hmac TEXT NOT NULL CHECK (length(previous_hmac)=64 AND previous_hmac NOT GLOB '*[^0-9a-f]*'),
    event_hmac TEXT NOT NULL CHECK (length(event_hmac)=64 AND event_hmac NOT GLOB '*[^0-9a-f]*')
);
CREATE INDEX IF NOT EXISTS idx_abdullah_audit_type_time ON audit_events(event_type, timestamp_utc);
