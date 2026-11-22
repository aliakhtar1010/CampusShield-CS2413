# CampusShield Authentication Experiment

## Password-guessing throttling

`runner.py` compares eight incorrect password attempts against:

1. A separate local Flask test-client baseline with password verification but no throttling.
2. The real CampusShield login route, using the configured persistent throttling.

Both profiles use the same synthetic username and Argon2 password hash. The protected profile uses a temporary SQLite database created for the run; it does not use or alter `campusshield.db`. The baseline and protected app are exercised only through Flask test clients. The runner does not start a network listener.

The report records attempts, password verification calls, response outcomes, per-request timings, and summary latency. The password itself and submitted guesses are not written to the report.

### Run

From the repository root in the project virtual environment:

```powershell
python -m experiments.runner
```

By default, the runner writes `results/password_throttle.json` and `results/password_throttle.csv`. Use `--output-dir` to choose another output directory.

### Expected security result

With the current five-failure lockout, the unthrottled baseline verifies every incorrect guess. The protected app verifies five guesses; the fifth triggers a lockout response, as do the remaining attempts. Thus, for eight attempts, the expected measurements are eight baseline checks, five protected checks, and four protected lockout responses.

### Interpretation and limitations

This is one controlled local run, not a statistical performance benchmark. The baseline intentionally models only the absence of throttling; it is not the former CampusShield application. Latency includes different route and database work, so it must not be interpreted as isolated throttling overhead. Results must be rerun after changes to authentication behavior, and measured outputs should not be fabricated or hand-edited.

## Tests

Run the focused experiment and existing authentication tests with:

```powershell
python -m pytest tests/test_experiment_runner.py tests/test_auth_integration.py tests/test_throttle_integration.py tests/test_mfa_integration.py
```
