-- Phase 4A: one encrypted contact record per fictional student.
-- Only new objects are created; existing tables and rows are untouched.
BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS student_private_records (
    student_id INTEGER PRIMARY KEY
        REFERENCES users(id) ON DELETE CASCADE,
    encrypted_email TEXT NOT NULL
        CHECK (length(encrypted_email) BETWEEN 1 AND 4096),
    encrypted_phone TEXT NOT NULL
        CHECK (length(encrypted_phone) BETWEEN 1 AND 4096),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Foreign keys alone cannot distinguish a student from an instructor.
CREATE TRIGGER IF NOT EXISTS naoshin_private_student_insert
BEFORE INSERT ON student_private_records
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM users
    WHERE id = NEW.student_id AND role = 'student'
)
BEGIN
    SELECT RAISE(ABORT, 'Private contact records require a student');
END;

CREATE TRIGGER IF NOT EXISTS naoshin_private_student_update
BEFORE UPDATE OF student_id ON student_private_records
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM users
    WHERE id = NEW.student_id AND role = 'student'
)
BEGIN
    SELECT RAISE(ABORT, 'Private contact records require a student');
END;

COMMIT;
