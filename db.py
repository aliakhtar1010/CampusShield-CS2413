
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("campusshield.db")


def get_connection():
    """
    Connect to SQLite with foreign key enforcement.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db():
    """
    Initialize CampusShield tables and indexes.

    Existing records are preserved.
    """
    conn = get_connection()

    try:
        conn.executescript("""
            -- USERS
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN (
                        'student',
                        'instructor',
                        'security_admin'
                    )
                ),
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1))
            );

            -- COURSES
            CREATE TABLE IF NOT EXISTS courses (
                id INTEGER PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL
            );

            -- INSTRUCTOR ASSIGNMENTS
            CREATE TABLE IF NOT EXISTS instructor_courses (
                instructor_id INTEGER NOT NULL
                    REFERENCES users(id),

                course_id INTEGER NOT NULL
                    REFERENCES courses(id),

                PRIMARY KEY (instructor_id, course_id)
            );

            -- ENROLLMENTS
            CREATE TABLE IF NOT EXISTS enrollments (
                id INTEGER PRIMARY KEY,
                student_id INTEGER NOT NULL
                    REFERENCES users(id),
                course_id INTEGER NOT NULL
                    REFERENCES courses(id),

                UNIQUE (student_id, course_id)
            );

            -- GRADES
            CREATE TABLE IF NOT EXISTS grades (
                id INTEGER PRIMARY KEY,
                enrollment_id INTEGER NOT NULL UNIQUE
                    REFERENCES enrollments(id),

                score INTEGER NOT NULL
                    CHECK (score BETWEEN 0 AND 100),

                updated_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            );

            -- ENCRYPTED MFA CREDENTIALS
            CREATE TABLE IF NOT EXISTS mfa_credentials (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id) ON DELETE CASCADE,

                encrypted_secret TEXT NOT NULL,

                last_used_step INTEGER NOT NULL
                    DEFAULT -1,

                is_enabled INTEGER NOT NULL DEFAULT 0
                    CHECK (is_enabled IN (0, 1)),

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            );

            -- PERSISTENT AUTHENTICATION THROTTLING
            CREATE TABLE IF NOT EXISTS auth_attempts (
                username TEXT NOT NULL,

                stage TEXT NOT NULL CHECK (
                    stage IN ('password', 'mfa')
                ),

                failure_count INTEGER NOT NULL DEFAULT 0
                    CHECK (failure_count >= 0),

                window_started INTEGER NOT NULL,

                locked_until INTEGER NOT NULL DEFAULT 0,

                last_failure INTEGER NOT NULL,

                PRIMARY KEY (username, stage)
            );

            -- INDEXES
            CREATE INDEX IF NOT EXISTS
                idx_enrollments_student
            ON enrollments(student_id);

            CREATE INDEX IF NOT EXISTS
                idx_instructor_courses_course
            ON instructor_courses(course_id);

            CREATE INDEX IF NOT EXISTS
                idx_auth_attempts_lockout
            ON auth_attempts(locked_until);
        """)

        conn.commit()

        tables = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """).fetchall()

        print("CampusShield database initialized.")
        print(
            "Tables:",
            ", ".join(row["name"] for row in tables)
        )

        foreign_keys_enabled = conn.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0]

        print(
            "Foreign keys enabled:",
            foreign_keys_enabled == 1
        )

    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
