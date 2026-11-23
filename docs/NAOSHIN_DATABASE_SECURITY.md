# CampusShield — Phase 4A: Database Security

**Owner:** Naoshin (Team 14, CS2413)  
**Branch:** `feature/naoshin-database-security`  
**Scope:** Additive student-private-record subsystem; no modifications to shared Flask routes, `db.py`, authentication, or teammates' modules.

## 1. Existing system and security gap

The original CampusShield application has SQLite foreign keys and grade constraints, parameterized queries for `/login` and `/records`, authenticated student-only academic-record retrieval, Argon2id authentication, and instructor/admin MFA. It does **not** include encrypted fictional student contact records or a reusable, separately authorized data-access service for them. Phase 4A adds those capabilities; it does not claim to repair an existing SQL-injection vulnerability in the login route.

## 2. New components

| File | Responsibility |
| --- | --- |
| `migrations/naoshin_private_records.sql` | Idempotently create `student_private_records` and student-role insert/ID-update triggers. |
| `scripts/init_private_records.py` | Apply migration only to an existing initialized CampusShield database; do not erase records. |
| `db_security/field_encryption.py` | Validate fictional email/phone and encrypt/decrypt using the existing `security.encryption.get_cipher()`. |
| `db_security/private_records.py` | Verify owner ID, active student role, parameterized SQLite reads and upserts; return decrypted data only after authorization. |
| `tests/test_private_records_migration.py`, `test_field_encryption.py`, `test_private_records.py`, `test_secure_queries.py`, `test_login_record_injection.py` | Migration, encryption, access-control, SQL-injection, and integrity regressions. |

The new table holds `student_id` (primary and foreign key to `users.id`), `encrypted_email`, `encrypted_phone`, and creation/update timestamps. Column checks require nonempty bounded tokens. One record is allowed per student; migration triggers reject inserting a record for a non-student user. SQLite foreign-key enforcement must remain enabled on every connection.

## 3. Protection and authorization flow

1. The caller obtains `authenticated_user_id` from the **server-managed, fully authenticated** Flask session, not a form field, query string, or claimed browser role. Pending MFA is insufficient.
2. `save_private_record(conn, authenticated_user_id=..., student_id=..., email=..., phone=...)` verifies ID types, identical owner/target IDs, and an active `student` role from the `users` table. It validates both values before encrypting them; SQL parameters carry all untrusted values. A conditional upsert rechecks account eligibility.
3. Fernet provides confidentiality and ciphertext authentication. Each encrypted JSON envelope contains a version, `student_id`, field name, and field value; the decryptor checks these bindings so a valid ciphertext moved between users or fields is rejected.
4. `get_private_record(conn, authenticated_user_id=..., student_id=...)` uses a parameterized ownership-and-role JOIN. Decryption occurs **only after** an authorized row is found. Invalid/misbound ciphertext produces `PrivateFieldDecryptionError`; missing/invalid key configuration produces `PrivateFieldConfigurationError`. Missing data and denied access have separate exceptions.
5. The caller owns `conn.commit()` on successful writes, `conn.rollback()` on failed writes, and `conn.close()`. The service does not manage the connection or expose a Flask route.

Example internal call (not a public endpoint):

```python
from db import get_connection
from db_security.private_records import get_private_record

conn = get_connection()
try:
    contact = get_private_record(
        conn,
        authenticated_user_id=session["user_id"],
        student_id=session["user_id"],
    )
finally:
    conn.close()
```

This assumes an already authenticated Flask request with a valid session. Ali must enforce the existing login/session and CSRF protections when integrating a UI or POST route; never read either ID from request arguments. Do not expose raw decrypted data or exception internals in logs or error pages.

## 4. Threats, controls, and limitations

| Threat | Control / evidence | Remaining limitation |
| --- | --- | --- |
| Read-only SQLite database theft | Email/phone stored as Fernet tokens, not plaintext | Compromise of both application and encryption key defeats confidentiality; metadata and grade data remain visible. |
| Ciphertext modification or substitution | Fernet authentication and encrypted owner/field binding | Database-level constraints alone cannot identify forged or malformed tokens; detected when decrypted. |
| Student accesses another student's contact | Server-derived identity, DB role/status check, parameterized owner-scoped query | Calling code must never substitute attacker-supplied IDs for the authenticated principal. |
| SQL-injection strings in usernames or IDs | Bound SQL parameters, type checks, hostile-input regression tests | Encryption does not itself prevent SQL injection; future dynamic queries must follow the same rules. |
| Duplicate/misassigned rows | Primary key, foreign key, student-role triggers | A privileged direct SQLite writer may bypass application validation and still write malformed tokens. |

Only fictional contact data is protected. Grades are not encrypted: existing grade joins, constraints, and authorization remain separate. Fernet tokens are randomized and not suitable for direct plaintext searching. Key rotation, backups, OS/file permissions, logs, network security, and deployment secret management remain operational responsibilities. Reusing the existing `CAMPUSSHIELD_ENCRYPTION_KEY` means its compromise affects both MFA secrets and the new fields.

## 5. Reproduce locally and preserve evidence

Use a local demo database containing **fictional data only**. Back up any database before applying a migration; do not run it against production data without review.

```powershell
py -m pip install -r requirements.txt pytest
py seed_demo.py
py scripts/init_private_records.py
py -m pytest -q tests/test_private_records_migration.py tests/test_field_encryption.py tests/test_private_records.py tests/test_secure_queries.py tests/test_login_record_injection.py
py -m pytest -q
```

The migration is additive and should be safe to rerun. New tests use temporary SQLite databases and generated temporary Fernet keys. Confirmed local commits: migration `d7fe875`, encryption `e050b60`, private-record service `9051361` (Checkpoint 4 hash to be recorded after committing). Recorded milestone results: **70 passed** after Checkpoint 1, **113 passed** after Checkpoint 2, **161 passed** after Checkpoint 3. Checkpoint 4's 32 new tests and full-suite success were reported by the developer; preserve the exact terminal output/screenshot of the latest run for final evidence (193 total expected).

## 6. Integration, review, and PR notes

Ali can (1) apply the owned migration after the normal demo/schema initialization, (2) add an authenticated, CSRF-protected private-contact form/blueprint, (3) derive the principal from `session["user_id"]` **after** the existing authentication/MFA flow, and (4) call the service with a SQLite connection, committing writes and translating permission/data errors into safe HTTP responses. These integration changes are **not part of this branch**. Rehan's instructor authorization and Abdullah's audit modules remain untouched.

**Before → after:** original login and academic-record queries were already parameterized; Phase 4A newly adds a constrained encrypted-contact table, context-bound Fernet encryption, owner-only private-record access service, and hostile-input/tampering regression evidence. Review the commit history and full pytest output in the PR before merging. **Do not push to `main` or self-merge.**
