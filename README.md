
# CampusShield-CS2413

**CS2413 Information Security — Final Project**  
University of New Brunswick | Fall 2026 | Team 14

## 1. Project Overview

CampusShield is a secure academic records portal developed using Python, Flask, and SQLite.

The project demonstrates how multiple security mechanisms can work together to protect student information, academic records, and authentication workflows.

Rather than relying solely on built-in security features, our team implemented and tested security controls across authentication, authorization, data protection, and security monitoring.

## 2. Security Features

### Authentication and MFA
- Password-based user authentication
- Time-based one-time passwords (TOTP)
- MFA replay prevention
- TOTP clock-drift tolerance
- Session management and logout
- Protection against inactive accounts

### Password Attack Protection
- Persistent login-attempt tracking
- Account lockout after repeated failed attempts
- Separate password and MFA failure counters
- Password-throttling experiment and evaluation

### Authorization and Academic Records
- Role-based access control (RBAC)
- Student-specific record isolation
- Instructor access restricted to assigned courses
- Server-side authorization for grade updates
- CSRF protection for sensitive operations

### Database Security
- Encryption of sensitive student contact information
- Parameterized SQL queries
- Input validation
- Database integrity constraints
- Protection against unauthorized record access

### Audit Logging and Threat Monitoring
- HMAC-SHA256 tamper-evident audit logs
- Chained security events
- External authenticated integrity checkpoint
- Detection of audit-log modification and truncation
- Rule-based security monitoring
- Audit events for authentication, MFA, account lockouts, access denials, and grade updates

## 3. Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Authentication | Passwords and TOTP MFA |
| Encryption | Python cryptography |
| Audit integrity | HMAC-SHA256 |
| Testing | pytest |
| Version control | Git and GitHub |

## 4. Project Structure

```text
CampusShield-CS2413/
├── app.py
├── db.py
├── routes/
│   └── instructor.py
├── security/
│   ├── audit.py
│   ├── audit_checkpoint.py
│   ├── audit_integration.py
│   ├── monitor.py
│   └── throttle.py
├── services/
├── migrations/
├── templates/
├── tests/
├── docs/
├── results/
└── README.md
```

## 5. Installation

### Prerequisites

- Python 3
- Git
- Required Python dependencies

### Clone the Repository

```bash
git clone https://github.com/aliakhtar1010/CampusShield-CS2413.git
cd CampusShield-CS2413
```

### Create a Virtual Environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## 6. Security Configuration

CampusShield uses environment variables for sensitive cryptographic keys.

Important variables include:

| Variable | Purpose |
|---|---|
| `CAMPUSSHIELD_SECRET_KEY` | Flask session signing |
| `CAMPUSSHIELD_ENCRYPTION_KEY` | Encryption of protected information |
| `CAMPUSSHIELD_AUDIT_KEY` | Audit-log integrity protection |

**Security requirements:**

- Never commit cryptographic keys to GitHub.
- Never store production secrets in source code.
- Keep the audit database and trusted checkpoint outside the repository.
- Preserve existing encryption and audit keys when reopening an initialized environment.
- Do not reinitialize an existing audit checkpoint.

### Audit Storage

The audit subsystem uses two separate locations:

```text
~/CampusShield-Secrets/audit.db
~/CampusShield-Secrets-Trusted/checkpoint.json
```

Separating these locations supports detection of unauthorized audit-history changes, assuming the checkpoint remains protected.

For a fresh installation, initialize the audit subsystem using the project's `ProtectedAudit` interface after configuring the audit key.

## 7. Running the Application

After configuring the required environment variables and initializing the application database:

```bash
python app.py
```

Open the local URL printed by Flask.

## 8. Testing and Evaluation

The project uses automated unit, integration, and adversarial security tests.

Run:

```bash
python -m pytest -q
```

### Final Integration Results

**November 23, 2026**

| Result | Count |
|---|---:|
| Passed tests | 332 |
| Passed subtests | 13 |
| Failed tests | 0 |

The tests cover:

- Authentication and MFA
- MFA replay prevention
- Password throttling and lockouts
- Role-based authorization
- Instructor grade management
- Student data isolation
- SQL injection defenses
- Encrypted student records
- Audit-chain integrity
- Audit tampering and checkpoint verification
- Security monitoring

The password-throttling experiment is implemented separately from the standard application tests.

## 9. Security Limitations

CampusShield is an educational security prototype, not a production-ready student information system.

Known limitations include:

- The audit subsystem requires environment configuration.
- Application database writes and audit database writes are not atomic across both databases.
- Audit integrity relies on protecting the audit key and trusted checkpoint.
- Coordinated rollback of both the audit database and its checkpoint may evade detection.
- Deployment-scale security controls and infrastructure hardening are outside the project scope.

## 10. Team Contributions

| Member | Contribution |
|---|---|
| Muhammad Ali Akhtar | Application integration, authentication/MFA integration, testing, documentation, final project coordination |
| Rehan | Role-based access control, instructor authorization, grade management |
| Naoshin | Database security, encrypted private student records, SQL injection defenses |
| Abdullah | Tamper-evident audit logging, integrity checkpoints, security monitoring |
| Nguyen | Password-throttling implementation and experimental evaluation |

## 11. Academic Context

Developed for **CS2413 — Information Security**, University of New Brunswick, Fall 2026.

**Instructor:** Dr. Fatemeh Khoda Parast

This project is intended for academic demonstration, security testing, and evaluation.
