import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import tempfile
from time import perf_counter_ns

os.environ.setdefault(
    "CAMPUSSHIELD_SECRET_KEY",
    "local-experiment-only-secret-key-not-for-production"
)

import app as app_module
import db
from experiments.baselines import (
    create_unthrottled_baseline_app
)
from security.passwords import (
    hash_password,
    verify_password
)
from security.throttle import (
    LOCKOUT_SECONDS,
    MAX_FAILURES,
    WINDOW_SECONDS
)


ATTEMPT_COUNT = 8
SYNTHETIC_USERNAME = "experiment_student"
SYNTHETIC_PASSWORD = "Local-Experiment-Password-2026!"


def _summarize(
    outcomes: list[dict[str, int | float | str]],
    password_checks: int
) -> dict:
    latencies = [
        outcome["latency_ms"]
        for outcome in outcomes
    ]

    return {
        "attempts": len(outcomes),
        "password_checks": password_checks,
        "invalid_responses": sum(
            outcome["outcome"] == "invalid"
            for outcome in outcomes
        ),
        "lockout_responses": sum(
            outcome["outcome"] == "locked_out"
            for outcome in outcomes
        ),
        "successful_logins": sum(
            outcome["outcome"] == "authenticated"
            for outcome in outcomes
        ),
        "total_latency_ms": round(sum(latencies), 3),
        "mean_latency_ms": round(
            sum(latencies) / len(latencies), 3
        ),
        "requests": outcomes
    }


def _run_unthrottled_baseline(
    password_hash: str,
    guesses: list[str]
) -> dict:
    password_checks = 0

    def counted_verify(stored_hash: str, password: str) -> bool:
        nonlocal password_checks
        password_checks += 1
        return verify_password(stored_hash, password)

    baseline_app = create_unthrottled_baseline_app(
        SYNTHETIC_USERNAME,
        password_hash,
        counted_verify
    )
    outcomes = []

    with baseline_app.test_client() as client:
        for guess in guesses:
            started = perf_counter_ns()
            response = client.post(
                "/login",
                data={
                    "username": SYNTHETIC_USERNAME,
                    "password": guess
                }
            )
            elapsed_ms = (
                perf_counter_ns() - started
            ) / 1_000_000

            if response.status_code == 200:
                outcome = "authenticated"
            elif response.status_code == 401:
                outcome = "invalid"
            else:
                raise RuntimeError(
                    "Unexpected response from local baseline: "
                    f"{response.status_code}"
                )

            outcomes.append({
                "attempt": len(outcomes) + 1,
                "outcome": outcome,
                "latency_ms": round(elapsed_ms, 3)
            })

    return _summarize(outcomes, password_checks)


def _run_protected_app(
    password_hash: str,
    guesses: list[str],
    database_path: Path
) -> dict:
    original_database_path = db.DB_PATH
    original_testing = app_module.app.config["TESTING"]
    original_verifier = app_module.verify_password
    password_checks = 0

    def counted_verify(stored_hash: str, password: str) -> bool:
        nonlocal password_checks
        password_checks += 1
        return original_verifier(stored_hash, password)

    try:
        db.DB_PATH = database_path
        db.init_db()

        connection = db.get_connection()
        try:
            connection.execute("""
                INSERT INTO users (
                    username, full_name, password_hash,
                    role, is_active
                )
                VALUES (?, ?, ?, 'student', 1)
            """, (
                SYNTHETIC_USERNAME,
                "Synthetic Experiment Student",
                password_hash
            ))
            connection.commit()
        finally:
            connection.close()

        app_module.app.config["TESTING"] = True
        app_module.verify_password = counted_verify
        outcomes = []

        with app_module.app.test_client() as client:
            client.get("/login")

            with client.session_transaction() as session:
                csrf_token = session["csrf_token"]

            for guess in guesses:
                started = perf_counter_ns()
                response = client.post(
                    "/login",
                    data={
                        "username": SYNTHETIC_USERNAME,
                        "password": guess,
                        "csrf_token": csrf_token
                    }
                )
                elapsed_ms = (
                    perf_counter_ns() - started
                ) / 1_000_000

                if (
                    b"Too many authentication attempts"
                    in response.data
                ):
                    outcome = "locked_out"
                elif (
                    b"Invalid username or password."
                    in response.data
                ):
                    outcome = "invalid"
                elif response.status_code == 302:
                    outcome = "authenticated"
                else:
                    raise RuntimeError(
                        "Unexpected response from protected app: "
                        f"HTTP {response.status_code}"
                    )

                outcomes.append({
                    "attempt": len(outcomes) + 1,
                    "outcome": outcome,
                    "latency_ms": round(elapsed_ms, 3)
                })

        return _summarize(outcomes, password_checks)

    finally:
        app_module.verify_password = original_verifier
        app_module.app.config["TESTING"] = original_testing
        db.DB_PATH = original_database_path


def run_password_throttle_experiment() -> dict:
    """Compare local unthrottled and protected login behavior."""
    password_hash = hash_password(SYNTHETIC_PASSWORD)
    guesses = [
        f"Incorrect-Local-Guess-{attempt:02d}"
        for attempt in range(1, ATTEMPT_COUNT + 1)
    ]

    baseline = _run_unthrottled_baseline(
        password_hash,
        guesses
    )

    with tempfile.TemporaryDirectory(
        prefix="campusshield-auth-experiment-"
    ) as temporary_directory:
        protected = _run_protected_app(
            password_hash,
            guesses,
            Path(temporary_directory) / "protected.sqlite3"
        )

    return {
        "schema_version": 1,
        "scenario": "password_guessing_throttle",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "network_access": False,
            "database": "temporary SQLite database"
        },
        "parameters": {
            "attempt_count": ATTEMPT_COUNT,
            "maximum_failures": MAX_FAILURES,
            "failure_window_seconds": WINDOW_SECONDS,
            "lockout_seconds": LOCKOUT_SECONDS,
            "account": "synthetic only"
        },
        "results": {
            "unthrottled_baseline": baseline,
            "protected_app": protected
        },
        "limitations": [
            "One local run; latency values are descriptive, not a statistical benchmark.",
            "The baseline is a separate test-client-only login implementation.",
            "Latency includes different route and database work, so it does not isolate throttling overhead."
        ]
    }


def write_results(
    report: dict,
    output_directory: Path
) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    json_path = output_directory / "password_throttle.json"
    csv_path = output_directory / "password_throttle.csv"

    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8"
    )

    columns = [
        "scenario",
        "profile",
        "attempts",
        "password_checks",
        "invalid_responses",
        "lockout_responses",
        "successful_logins",
        "total_latency_ms",
        "mean_latency_ms"
    ]

    with csv_path.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=columns
        )
        writer.writeheader()

        for profile, metrics in report["results"].items():
            writer.writerow({
                "scenario": report["scenario"],
                "profile": profile,
                **{
                    column: metrics[column]
                    for column in columns
                    if column in metrics
                }
            })

    return json_path, csv_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the local-only CampusShield password-throttle experiment."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory for JSON and CSV results (default: results)"
    )
    args = parser.parse_args()

    report = run_password_throttle_experiment()
    json_path, csv_path = write_results(
        report,
        args.output_dir
    )

    print(f"JSON results: {json_path}")
    print(f"CSV results: {csv_path}")
    for profile, metrics in report["results"].items():
        print(
            f"{profile}: password checks="
            f"{metrics['password_checks']}, "
            f"lockout responses={metrics['lockout_responses']}"
        )


if __name__ == "__main__":
    main()
