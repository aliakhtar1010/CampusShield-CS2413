
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("campusshield.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Enforce relationships between database tables
    conn.execute("PRAGMA foreign_keys = ON")

    return conn


def init_db():
    conn = get_connection()

    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN ('student', 'instructor', 'security_admin')
                ),
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS courses (
                id INTEGER PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS instructor_courses (
                instructor_id INTEGER NOT NULL REFERENCES users(id),
                course_id INTEGER NOT NULL REFERENCES courses(id),
                PRIMARY KEY (instructor_id, course_id)
            );

            CREATE TABLE IF NOT EXISTS enrollments (
                id INTEGER PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES users(id),
                course_id INTEGER NOT NULL REFERENCES courses(id),
                UNIQUE (student_id, course_id)
            );

            CREATE TABLE IF NOT EXISTS grades (
                id INTEGER PRIMARY KEY,
                enrollment_id INTEGER NOT NULL UNIQUE
                    REFERENCES enrollments(id),
                score INTEGER NOT NULL
                    CHECK (score BETWEEN 0 AND 100),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_enrollments_student
            ON enrollments(student_id);
        """)

        conn.commit()

        tables = conn.execute("""
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """).fetchall()

        print("CampusShield database initialized.")
        print("Tables:", ", ".join(row[0] for row in tables))
        print(
            "Foreign keys enabled:",
            conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        )

    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
