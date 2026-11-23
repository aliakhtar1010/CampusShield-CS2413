import json

import db
from experiments.runner import (
    ATTEMPT_COUNT,
    run_password_throttle_experiment,
    write_results
)
from security.throttle import MAX_FAILURES


def test_throttle_experiment_measures_lockout_and_writes_results(
    tmp_path
):
    original_database_path = db.DB_PATH
    report = run_password_throttle_experiment()

    assert db.DB_PATH == original_database_path

    baseline = report["results"]["unthrottled_baseline"]
    protected = report["results"]["protected_app"]

    assert baseline["attempts"] == ATTEMPT_COUNT
    assert baseline["password_checks"] == ATTEMPT_COUNT
    assert baseline["lockout_responses"] == 0

    assert protected["attempts"] == ATTEMPT_COUNT
    assert protected["password_checks"] == MAX_FAILURES
    assert protected["invalid_responses"] == MAX_FAILURES - 1
    assert protected["lockout_responses"] == (
        ATTEMPT_COUNT - MAX_FAILURES + 1
    )
    assert protected["successful_logins"] == 0

    json_path, csv_path = write_results(
        report,
        tmp_path
    )

    saved_report = json.loads(
        json_path.read_text(encoding="utf-8")
    )
    saved_csv = csv_path.read_text(encoding="utf-8")

    assert saved_report["scenario"] == "password_guessing_throttle"
    assert "unthrottled_baseline" in saved_csv
    assert "protected_app" in saved_csv
    saved_json = json_path.read_text(encoding="utf-8")
    assert "Local-Experiment-Password-2026!" not in saved_json
