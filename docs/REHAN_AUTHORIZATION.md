# CampusShield — Phase 3: Authorization and Instructor Grade Management

## 1. Overview

Phase 3 implements centralized role-based access control (RBAC), secure instructor course management, and an instructor dashboard for CampusShield.

The implementation restricts access to academic records according to authenticated user identity, assigned roles, and course ownership.

## 2. Implemented Components

### Centralized Authorization

**File:** `security/authorization.py`

Implements reusable authorization functions:

- `authenticated_user_id()` — Retrieves the fully authenticated user ID from the Flask session.
- `get_user()` — Retrieves an active user from the database.
- `has_role()` — Verifies the user's role.
- `can_view_record()` — Checks whether a student can access their own record.
- `can_manage_course()` — Checks whether an instructor is assigned to a course.
- `can_update_grade()` — Checks whether an instructor is authorized to modify an enrollment's grade.

### Secure Grade Management

**File:** `services/grade_service.py`

Implements:

- `get_instructor_courses()` — Retrieves courses assigned to the authenticated instructor.
- `get_course_students()` — Retrieves enrolled students and their grades for an authorized course.
- `update_grade()` — Updates grades only when the instructor has permission.

Grade values are restricted to integers from 0 to 100.

Grade updates use parameterized SQL queries and database-side authorization checks.

### Instructor Dashboard

**Files:**

- `routes/instructor.py`
- `templates/instructor_dashboard.html`

The dashboard allows authorized instructors to:

1. View assigned courses.
2. View enrolled students and existing grades.
3. Submit grade updates.
4. Access only courses assigned to them.

Instructor endpoints reject unauthenticated and unauthorized requests.

## 3. Security Controls

| Security control         | Implementation                                           |
| ------------------------ | -------------------------------------------------------- |
| Authentication           | Requires `session["user_id"]`                            |
| MFA enforcement          | Pending-MFA sessions do not qualify as authenticated     |
| RBAC                     | Role checks use the database                             |
| Course authorization     | Instructor-course relationships are verified             |
| Grade authorization      | SQL update is restricted to assigned courses             |
| Input validation         | Grade values must be integers from 0 to 100              |
| CSRF protection          | Grade-update forms require a valid session CSRF token    |
| SQL injection prevention | Parameterized SQL statements                             |
| Inactive accounts        | Inactive instructors are denied access                   |
| Permission revocation    | Revoked course assignments prevent further grade updates |

## 4. Testing and Results

Testing was performed using pytest and isolated SQLite databases.

| Test suite                     | Passing tests |
| ------------------------------ | ------------: |
| Existing CampusShield baseline |            62 |
| Authorization tests            |             6 |
| Grade-service tests            |            17 |
| Instructor route tests         |            26 |
| **Total**                      |       **111** |

**Final local result:** 111 passed in 18.29 seconds, with no failures.

Tests include unauthorized access, pending-MFA sessions, role restrictions, cross-course grade modifications, invalid grades, missing or incorrect CSRF tokens, inactive instructors, and revoked course assignments.

## 5. Integration Requirements

The instructor dashboard is implemented as a Flask blueprint.

The main application maintainer must register the blueprint in `app.py`:

```python
from routes.instructor import instructor_bp
app.register_blueprint(instructor_bp)
```

The home page should also provide a navigation link for authenticated instructors:

```python
url_for("instructor.dashboard")
```

These shared-file changes are intentionally excluded from Rehan's feature branch to avoid conflicts with other team members.

## 6. Limitations and Remaining Work

- The instructor blueprint has been tested using a standalone Flask test application.
- Integration testing inside the main CampusShield Flask application remains pending.
- Blueprint registration and home page navigation must be completed by the main application maintainer.
- The implementation provides grade-update controls but does not introduce a dedicated grade-change audit log.
- The existing application authentication and MFA mechanisms are reused rather than reimplemented.

## 7. Git Contributions

**Branch:** `feature/rehan-authorization`

| Commit    | Description                           |
| --------- | ------------------------------------- |
| `da2f640` | Centralized RBAC authorization policy |
| `472e216` | Secure instructor grade management    |
| `e833583` | Instructor dashboard and route tests  |
| `1d1ef74` | Additional security regression tests  |

## 8. Conclusion

Phase 3 provides centralized authorization and secure instructor grade management while enforcing role, course, and enrollment-level access restrictions.

All 111 local tests pass. Final application integration and end-to-end verification remain pending before the feature can be considered fully deployed.
