
from flask import Flask, render_template
from db import get_connection

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/records")
def academic_records():
    conn = get_connection()

    try:
        # Demonstration query using a fixed fictional student.
        # Authentication and access control come later.
        records = conn.execute("""
            SELECT
                u.full_name AS student_name,
                c.code AS course_code,
                c.title AS course_title,
                g.score AS grade
            FROM grades g
            JOIN enrollments e ON g.enrollment_id = e.id
            JOIN users u ON e.student_id = u.id
            JOIN courses c ON e.course_id = c.id
            WHERE u.username = ?
            ORDER BY c.code
        """, ("student01",)).fetchall()

    finally:
        conn.close()

    return render_template("records.html", records=records)


if __name__ == "__main__":
    app.run(debug=True)
