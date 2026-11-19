
import sqlite3
from pathlib import Path

# CampusShield local SQLite database
DB_PATH = Path(__file__).with_name("campusshield.db")


def get_connection():
    """
    Create a SQLite connection with row-based access
    and foreign key enforcement enabled.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # SQLite requires foreign keys to be enabled
    # separately for each database connection.
    conn.execute("PRAGMA foreign_keys = ON")

    return conn


def init_db():
    """
    Initialize the CampusShield database.

    Existing tables and records are preserved.
    Missing tables and indexes are created.
    """
    conn = get_connection()

    try:
        conn.executescript("""
            -- ======================================
            -- USERS
            -- ======================================
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

            -- ======================================
            -- COURSES
            -- ======================================
            CREATE TABLE IF NOT EXISTS courses (
                id INTEGER PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL
            );

            -- ======================================
            -- INSTRUCTOR ASSIGNMENTS
            -- ======================================
            CREATE TABLE IF NOT EXISTS instructor_courses (
                instructor_id INTEGER NOT NULL
                    REFERENCES users(id),

                course_id INTEGER NOT NULL
                    REFERENCES courses(id),

                PRIMARY KEY (
                    instructor_id,
                    course_id
                )
            );

            -- ======================================
            -- STUDENT ENROLLMENTS
            -- ======================================
            CREATE TABLE IF NOT EXISTS enrollments (
                id INTEGER PRIMARY KEY,

                student_id INTEGER NOT NULL
                    REFERENCES users(id),

                course_id INTEGER NOT NULL
                    REFERENCES courses(id),

                UNIQUE (
                    student_id,
                    course_id
                )
            );

            -- ======================================
            -- ACADEMIC GRADES
            -- ======================================
            CREATE TABLE IF NOT EXISTS grades (
                id INTEGER PRIMARY KEY,

                enrollment_id INTEGER NOT NULL UNIQUE
                    REFERENCES enrollments(id),

                score INTEGER NOT NULL
                    CHECK (
                        score BETWEEN 0 AND 100
                    ),

                updated_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            );

            -- ======================================
            -- MFA CREDENTIALS
            -- ======================================
            CREATE TABLE IF NOT EXISTS mfa_credentials (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                encrypted_secret TEXT NOT NULL,

                last_used_step INTEGER NOT NULL
                    DEFAULT -1,

                is_enabled INTEGER NOT NULL DEFAULT 0
                    CHECK (
                        is_enabled IN (0, 1)
                    ),

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            );

            -- ======================================
            -- INDEXES
            -- ======================================
            CREATE INDEX IF NOT EXISTS
                idx_enrollments_student
            ON enrollments(student_id);

            CREATE INDEX IF NOT EXISTS
                idx_instructor_courses_course
            ON instructor_courses(course_id);
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
