# Containerized CLI Login System Implementation Specification

> **Stack:** Go + PostgreSQL + Docker + Optional TOTP-based 2FA

---

## 1. Purpose and Scope

This document is an implementation-ready specification for the CLI login backend assignment: a secure, interactive command-line login system with registration, password authentication, optional TOTP-based two-factor authentication, account lockout, session management, PostgreSQL persistence, and Docker support.

The document intentionally fixes the technology choices, folder structure, database schema, CLI commands, function responsibilities, configuration values, and edge-case behavior so that a developer or coding agent can implement the project without making major architectural decisions.

The specification follows the assignment requirements: registration and login, optional Google Authenticator-compatible TOTP, password hashing, account lockout, configurable sessions, interactive CLI history/tab completion, Dockerized persistent PostgreSQL database, README, and schema/migrations.

---

## 2. Fixed Technology Decisions

| Area | Decision | Reason |
| --- | --- | --- |
| **Language** | Go 1.23 or newer stable Go version available in the environment | Required by the assignment and suitable for a small secure CLI. |
| **CLI framework** | `github.com/chzyer/readline` | Provides interactive prompt, command history, and tab completion. |
| **Database** | PostgreSQL 16 (Alpine container) | Robust relational database executed via Docker Compose with volume persistence. |
| **PostgreSQL driver** | `github.com/jackc/pgx/v5/stdlib` | Modern, high-performance pure-Go PostgreSQL driver compatible with standard `database/sql`. Avoids CGO requirements. |
| **Password hashing** | `golang.org/x/crypto/bcrypt` | Widely used password hashing algorithm with built-in cost control. |
| **TOTP** | `github.com/pquerna/otp/totp` | Supports Google Authenticator-compatible TOTP generation and validation. |
| **QR code** | `github.com/skip2/go-qrcode` | Generates a QR image from the otpauth URI. |
| **Session token** | `crypto/rand` | Generates cryptographically secure random session tokens. |
| **Configuration** | Environment variables with safe defaults | Easy to configure locally and in Docker Compose. |
| **Container** | Dockerfile + docker-compose.yml | Multi-container setup (app + PostgreSQL) with healthchecks and reproducible execution. |

---

## 3. Functional Requirements

- A user can register with a unique username and password.
- Passwords are never stored in plaintext; only bcrypt hashes are stored.
- A user can log in using username and password.
- If TOTP is enabled, the user must also provide a valid TOTP code.
- After repeated failed login attempts, the account is temporarily locked.
- A successful login creates a session with an expiration time.
- The session timeout is configurable.
- Authenticated commands require a valid, non-expired session.
- A user can enable or disable TOTP after login.
- The CLI provides help, history, and tab completion.
- The database persists across container restarts through a Docker volume (`postgres_data`).

---

## 4. Non-Functional Security Rules

- Never print passwords, password hashes, TOTP secrets, session tokens, or complete otpauth URIs to logs.
- Use generic login failure messages so attackers cannot easily discover whether a username exists.
- Use UTC timestamps (`TIMESTAMPTZ`) in the database.
- Use parameterized SQL queries only (`$1`, `$2`, ...); never concatenate user input into SQL.
- Use `crypto/rand` for session tokens and TOTP secret generation through the TOTP library.
- Use a small TOTP clock-skew window. Configure `Skew=1`, which permits the previous, current, and next 30-second period.
- Do not allow a locked account to bypass the lock by entering a correct password.
- Do not allow authenticated commands after session expiry.
- Do not reveal whether a user has TOTP enabled before the password step succeeds.
- Use transactions for security-sensitive updates such as failed-attempt counters and TOTP enrollment.

---

## 5. Required Project Structure

```text
cli-login/
├── cmd/
│   └── clilogin/
│       └── main.go
├── internal/
│   ├── app/
│   │   └── app.go
│   ├── auth/
│   │   ├── service.go
│   │   ├── password.go
│   │   ├── lockout.go
│   │   ├── session.go
│   │   └── totp.go
│   ├── cli/
│   │   ├── shell.go
│   │   ├── commands.go
│   │   ├── prompts.go
│   │   └── output.go
│   ├── config/
│   │   └── config.go
│   ├── database/
│   │   ├── db.go
│   │   ├── migrations.go
│   │   └── repositories.go
│   ├── models/
│   │   └── models.go
│   └── security/
│       ├── random.go
│       └── sanitize.go
├── migrations/
│   └── 001_initial.sql
├── tests/
│   ├── auth_test.go
│   ├── lockout_test.go
│   ├── session_test.go
│   └── totp_test.go
├── data/
│   └── .gitkeep
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
├── .env.example
├── .gitignore
└── README.md
```

---

## 6. Responsibility of Each File

| File | Responsibility |
| --- | --- |
| `cmd/clilogin/main.go` | Load configuration, open PostgreSQL database, run migrations, construct services, start the CLI shell. |
| `internal/app/app.go` | Application dependency container holding config, repositories, auth service, and shell. |
| `internal/config/config.go` | Read environment variables and validate configuration. |
| `internal/models/models.go` | Define User, Session, and pending TOTP enrollment structures. |
| `internal/database/db.go` | Open PostgreSQL connection pool (`*sql.DB`), configure pool settings, and verify connectivity with retry/backoff. |
| `internal/database/migrations.go` | Apply SQL migrations in order. |
| `internal/database/repositories.go` | All SQL access for users and sessions using PostgreSQL dialect and parameterized placeholders (`$1, $2, ...`). |
| `internal/auth/service.go` | Orchestrate registration, login, logout, and authenticated operations. |
| `internal/auth/password.go` | Hash and compare passwords using bcrypt. |
| `internal/auth/lockout.go` | Implement failed-attempt counting, lock checking, and lock expiration. |
| `internal/auth/session.go` | Create, validate, expire, and revoke sessions. |
| `internal/auth/totp.go` | Generate TOTP enrollment data, validate codes, enable/disable TOTP. |
| `internal/cli/shell.go` | Run the readline loop and route commands based on authentication state. |
| `internal/cli/commands.go` | Define command names, argument rules, and handlers. |
| `internal/cli/prompts.go` | Read usernames, passwords, and OTP codes safely. |
| `internal/cli/output.go` | Centralize human-readable success/error messages. |
| `internal/security/random.go` | Generate secure random bytes and session tokens. |
| `internal/security/sanitize.go` | Normalize input and prevent accidental secret output. |

---

## 7. Configuration

```env
APP_NAME=cli-login
DB_HOST=postgres
DB_PORT=5430
DB_USER=cli_user
DB_PASSWORD=cli_secret
DB_NAME=cli_login_db
DB_SSLMODE=disable
DB_MAX_OPEN_CONNS=10
DB_MAX_IDLE_CONNS=5
SESSION_TIMEOUT_MINUTES=30
MAX_FAILED_ATTEMPTS=5
LOCKOUT_MINUTES=15
BCRYPT_COST=12
TOTP_PERIOD_SECONDS=30
TOTP_SKEW_PERIODS=1
TOTP_ISSUER=CLI Login
READLINE_HISTORY_FILE=/app/data/.cli_history
```

Construct the PostgreSQL DSN using standard parameters (e.g. `postgres://<user>:<password>@<host>:<port>/<dbname>?sslmode=<sslmode>`).

Defaults must be used when variables are absent. Invalid values must stop startup with a clear configuration error. Do not silently accept negative values or zero values where they are unsafe.

---

## 8. Database Schema

Create `migrations/001_initial.sql` with the following schema:

```sql
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        CITEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    registered_at   TIMESTAMPTZ NOT NULL,
    last_login_at   TIMESTAMPTZ NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ NULL,
    totp_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret     TEXT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
```

Store timestamps as `TIMESTAMPTZ` in UTC (handled directly through Go `time.Time`). `CITEXT` is used for case-insensitive unique usernames. Store the hash of the session token rather than the raw token. TOTP secrets must be encrypted at rest in a production-grade system; for this assignment, document the limitation clearly if application-level encryption is not implemented.

---

## 9. Core Data Models

```go
type User struct {
    ID             int64
    Username       string
    PasswordHash   string
    RegisteredAt   time.Time
    LastLoginAt    *time.Time
    FailedAttempts int
    LockedUntil    *time.Time
    TOTPEnabled    bool
    TOTPSecret     *string
}

type Session struct {
    ID        int64
    UserID    int64
    TokenHash string
    CreatedAt time.Time
    ExpiresAt time.Time
    RevokedAt *time.Time
}

type AuthenticatedSession struct {
    UserID    int64
    Username  string
    Token     string
    ExpiresAt time.Time
}
```

---

## 10. CLI State Machine

| State | Allowed commands |
| --- | --- |
| **Unauthenticated** | `register`, `login`, `help`, `exit` |
| **Authenticated** | `whoami`, `enable-2fa`, `disable-2fa`, `logout`, `help`, `exit` |

The shell must reject commands that are not valid in the current state. It should not terminate on ordinary user mistakes; it should print a helpful error and continue.

---

## 11. CLI Command Specifications

### `register`

Create a user.

**Example:**
```text
> register
Username: aditya
Password: ********
Confirm password: ********

Registration successful.
```

**Rules:**
- Trim surrounding whitespace from username.
- Reject empty usernames.
- Allow only 3–32 characters: letters, digits, underscore, hyphen, and period.
- Reject passwords shorter than 12 characters.
- Require password confirmation to match.
- Check duplicate usernames case-insensitively (enforced by `CITEXT UNIQUE`).
- Hash password with bcrypt before insertion.
- Do not automatically log the user in.

---

### `login`

Authenticate with password and optional TOTP.

**Example:**
```text
> login
Username: aditya
Password: ********
TOTP code (if enabled): 123456

Login successful.
Username: aditya
Registration date: 2026-09-15T10:00:00Z
MFA status: enabled
Session expires: 2026-09-15T10:30:00Z
Last login: 2026-09-15T09:45:00Z
```

**Rules:**
- Look up user by normalized username.
- Check lockout before password verification.
- Use a generic failure response for unknown users or wrong passwords.
- On password failure, atomically increment `failed_attempts`.
- Lock the account when the configured threshold is reached.
- If password succeeds and TOTP is enabled, request a six-digit code.
- If TOTP fails, treat the complete login as failed and increment the failed-attempt counter.
- Only reset `failed_attempts` after the entire login flow succeeds.
- Create a session only after password and TOTP checks succeed.
- Update `last_login_at` only after successful login.

---

### `whoami`

Display current user information.

**Example:**
```text
> whoami
Username: aditya
Registration date: 2026-09-15T10:00:00Z
MFA status: enabled
Session expires: 2026-09-15T10:30:00Z
Last login: 2026-09-15T09:45:00Z
```

**Rules:**
- Validate session first.
- Read current user details from the database.
- Never display password hash or TOTP secret.
- If session expired, clear local session and require login.

---

### `enable-2fa`

Enroll the current user in TOTP.

**Example:**
```text
> enable-2fa
A QR code has been generated. Scan it with Google Authenticator.
Enter the 6-digit code to confirm: 123456

2FA enabled successfully.
```

**Rules:**
- Require a valid session.
- Reject if TOTP is already enabled.
- Generate a new TOTP key.
- Create an otpauth URI using issuer and username.
- Display a QR code in a terminal-compatible way or save a temporary PNG and print its path.
- Display the secret only if necessary and warn the user to protect it.
- Ask for a code to verify enrollment.
- Do not save `totp_enabled=true` until verification succeeds.
- On success, persist the secret and set `totp_enabled=true` in one transaction.
- On failure, discard the pending secret and do not change the account.

---

### `disable-2fa`

Disable TOTP for the current user.

**Example:**
```text
> disable-2fa
Enter current password: ********
Enter current TOTP code: 123456

2FA disabled successfully.
```

**Rules:**
- Require a valid session.
- Reject if TOTP is not enabled.
- Require the current password again.
- Require a valid current TOTP code.
- Only then clear `totp_secret` and set `totp_enabled=false`.
- Do not disable MFA based only on an active session.

---

### `logout`

End the current session.

**Example:**
```text
> logout
Logged out successfully.
```

**Rules:**
- Revoke the session in the database.
- Clear the in-memory token and authenticated user.
- Return to the unauthenticated command set.
- Make logout idempotent: if already logged out, print a harmless message.

---

### `help`

Show commands available in the current state.

**Example:**
```text
Available commands:
  register    Create a new user
  login       Log in
  help        Show this help
  exit        Exit the application
```

**Rules:**
- Show only commands valid for the current state.
- Include short descriptions.
- Do not expose internal implementation details.

---

### `exit`

Terminate the CLI.

**Example:**
```text
> exit
Goodbye.
```

**Rules:**
- If authenticated, revoke the current session before exiting.
- Close the database and readline resources cleanly.

---

## 12. Password Handling

Use bcrypt. The password flow must be:

1. Read the password using a hidden-input prompt; do not echo it.
2. Validate password policy before hashing.
3. Hash with `bcrypt.GenerateFromPassword([]byte(password), configuredCost)`.
4. Store only the resulting hash.
5. Use `bcrypt.CompareHashAndPassword` during login.
6. Never log the plaintext password or hash.

Recommended assignment policy: minimum 12 characters. Do not impose unnecessary composition rules such as requiring a symbol unless the assignment specifically asks for them.

---

## 13. Account Lockout Design

A failed attempt means a login flow that does not fully authenticate. This includes a wrong password, an unknown username, or a wrong TOTP code after the password was correct. For unknown usernames, do not update a real account; use a dummy bcrypt comparison to reduce timing differences.

| Setting | Default |
| --- | --- |
| **Maximum failed attempts** | 5 |
| **Lockout duration** | 15 minutes |
| **Counter reset** | After complete successful login |
| **Lock check** | Before password verification |
| **Lock behavior** | Reject login even if password is correct |

### Algorithm

1. Load the user record.
2. If `locked_until` is not null and now is earlier than `locked_until`, reject with: `'Account temporarily locked. Try again later.'`
3. If `locked_until` is present but expired, clear `locked_until` and reset `failed_attempts` to zero.
4. Verify password.
5. If password is wrong, increment `failed_attempts` atomically.
6. If `failed_attempts` reaches the threshold, set `locked_until = now + lockout duration`.
7. If TOTP is required but invalid, count the login as failed using the same mechanism.
8. On complete success, set `failed_attempts = 0`, `locked_until = NULL`, and update `last_login_at`.

Avoid revealing the exact remaining number of attempts because that can help attackers. A simple generic message is preferable.

---

## 14. Session Management Design

A session is the server-side record that proves the user has already completed login. The CLI keeps the raw token in memory, while the database stores only its hash.

### Session Creation

1. Generate 32 random bytes using `crypto/rand`.
2. Encode the token using `base64.RawURLEncoding`.
3. Hash the token with SHA-256 before storing it.
4. Set `created_at = now UTC`.
5. Set `expires_at = now + SESSION_TIMEOUT_MINUTES`.
6. Insert the session record.
7. Keep the raw token only in the current process memory.

### Session Validation (Before Every Authenticated Command)

1. If there is no in-memory token, reject the command.
2. Hash the token and query the `sessions` table.
3. Reject if no row exists.
4. Reject if `revoked_at` is not null.
5. Reject if `expires_at <= current UTC time`.
6. If rejected because of expiry, clear local authentication state.
7. Otherwise load the user and continue.

The timeout is absolute, not sliding: using commands does not extend the expiration time. This is simpler and predictable for the assignment.

---

## 15. TOTP Design

TOTP is a time-based one-time password. During enrollment, the server creates a random shared secret. The authenticator app stores that secret and independently calculates a six-digit code from the secret and current time. The server performs the same calculation and compares the submitted code.

Use the `pquerna/otp` library rather than implementing the cryptographic algorithm manually.

```go
key, err := totp.Generate(totp.GenerateOpts{
    Issuer:      cfg.TOTPIssuer,
    AccountName: username,
    Period:      uint(cfg.TOTPPeriodSeconds),
    Digits:      otp.DigitsSix,
    Algorithm:   otp.AlgorithmSHA1,
})
```

Validation should use a small skew window:

```go
valid, err := totp.ValidateCustom(
    submittedCode,
    secret,
    time.Now().UTC(),
    totp.ValidateOpts{
        Period:    uint(cfg.TOTPPeriodSeconds),
        Skew:      uint(cfg.TOTPSkewPeriods),
        Digits:    otp.DigitsSix,
        Algorithm: otp.AlgorithmSHA1,
    },
)
```

With `Period=30` and `Skew=1`, the verifier can accept the previous, current, or next 30-second time step. It does not store the previous code or previous window; it recalculates possible codes from the stored secret and the current time.

### Enrollment Flow

1. Generate a new TOTP key.
2. Build the otpauth URI from the key.
3. Generate a QR image from the URI.
4. Show the QR image or its file path.
5. Ask the user to enter the current six-digit code.
6. Validate the code using the configured skew.
7. Only after successful validation, save the secret and enable TOTP.

> [!IMPORTANT]
> A TOTP secret cannot be stored as a one-way hash because the server needs the original secret to calculate future codes. In a stronger production implementation, encrypt the secret using an application key kept outside the database.

---

## 16. QR Code and Terminal Behavior

- Generate the QR image as a PNG using `go-qrcode`.
- Save it temporarily under the configured data directory, for example `/app/data/totp-aditya.png`.
- Print the absolute path and tell the user to open it and scan it.
- If terminal rendering is implemented, render the QR using block characters, but keep the PNG fallback because terminal capabilities vary.
- Delete temporary QR files after successful enrollment or after a short cleanup period.
- Never place the QR image or otpauth URI in application logs.

---

## 17. Exact Service Interfaces

```go
type AuthService interface {
    Register(ctx context.Context, username, password, confirm string) error
    Login(ctx context.Context, username, password, totpCode string) (*AuthenticatedSession, error)
    Logout(ctx context.Context, rawToken string) error
    GetCurrentUser(ctx context.Context, rawToken string) (*User, *Session, error)
    BeginTOTPEnrollment(ctx context.Context, rawToken string) (*TOTPEnrollment, error)
    ConfirmTOTPEnrollment(ctx context.Context, rawToken, code string, enrollment *TOTPEnrollment) error
    DisableTOTP(ctx context.Context, rawToken, password, code string) error
}

type TOTPEnrollment struct {
    Secret  string
    QRPath  string
    Issuer  string
    Account string
}
```

The CLI should call these service methods and should not contain SQL, bcrypt, TOTP, or session logic directly.

---

## 18. Repository Methods

```go
type UserRepository interface {
    Create(ctx context.Context, user *User) error
    FindByUsername(ctx context.Context, username string) (*User, error)
    FindByID(ctx context.Context, id int64) (*User, error)
    RecordFailedLogin(ctx context.Context, userID int64, now time.Time, maxAttempts int, lockDuration time.Duration) error
    ResetLoginFailures(ctx context.Context, userID int64, now time.Time) error
    UpdateTOTP(ctx context.Context, userID int64, enabled bool, secret *string) error
}

type SessionRepository interface {
    Create(ctx context.Context, session *Session) error
    FindByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
    Revoke(ctx context.Context, tokenHash string, now time.Time) error
}
```

---

## 19. Error Handling Rules

Detailed database errors may be logged only in a controlled development mode. Do not expose SQL statements, filesystem paths, stack traces, or secrets to the user.

| Situation | User-facing message |
| --- | --- |
| Unknown command | `Unknown command. Type 'help' to see available commands.` |
| Invalid command state | `You must be logged in to use this command.` |
| Duplicate username | `Registration failed: username is already unavailable.` |
| Weak password | `Registration failed: password does not meet the minimum requirements.` |
| Wrong login details | `Login failed: invalid credentials.` |
| Locked account | `Account temporarily locked. Try again later.` |
| Expired session | `Session expired. Please log in again.` |
| Invalid TOTP | `Authentication failed: invalid verification code.` |
| TOTP already enabled | `2FA is already enabled for this account.` |
| TOTP not enabled | `2FA is not enabled for this account.` |
| Database failure | `An internal error occurred. Please try again.` |

---

## 20. Edge Cases and Required Behavior

| Edge case | Required behavior |
| --- | --- |
| **Username with leading/trailing spaces** | Trim spaces before validation; store the normalized username. |
| **Username case differences** | Treat usernames case-insensitively; `Aditya` and `aditya` are the same account (backed by `CITEXT`). |
| **Empty username/password** | Reject before database access. |
| **Password confirmation mismatch** | Reject registration without creating a row. |
| **Duplicate registration race** | Rely on the `UNIQUE` constraint and map the database error to a generic duplicate message. |
| **Wrong password repeatedly** | Increment `failed_attempts`; lock after threshold. |
| **Wrong TOTP after correct password** | Count the complete login as failed; do not create a session. |
| **Correct password during lockout** | Reject until `locked_until` has passed. |
| **Lockout duration passed** | Clear lockout state on the next login attempt. |
| **Application restarts during lockout** | Lockout remains because it is stored in PostgreSQL. |
| **Application restarts with active session** | The database session exists, but the CLI has lost the raw token; user must log in again. |
| **Session expires while CLI is open** | The next authenticated command detects expiry and returns to unauthenticated state. |
| **Logout twice** | Do not crash; show a harmless message. |
| **Enable 2FA and enter wrong code** | Do not enable MFA and do not persist the pending secret. |
| **Enable 2FA twice** | Reject the second attempt unless a separate reset flow is implemented. |
| **Disable 2FA with wrong password** | Do not change MFA state. |
| **Disable 2FA with wrong TOTP** | Do not change MFA state. |
| **Malformed TOTP input** | Reject unless it is exactly six numeric digits. |
| **TOTP code at a time-window boundary** | Use `Skew=1` to tolerate a small boundary delay. |
| **System clock incorrect** | Document that server clock accuracy matters; use UTC and synchronize the container host clock. |
| **PostgreSQL connection failure on startup** | Wait for PostgreSQL healthcheck via Docker Compose or retry with backoff in `db.go`; fail startup with a clear error if unreachable. |
| **Database permission failure** | Fail startup with a clear actionable error. |
| **Container restart** | Data persists because PostgreSQL data directory is mounted to a named Docker volume (`postgres_data`). |
| **Ctrl+C or EOF** | Gracefully revoke the current session, close readline, and close the database connection pool. |
| **Very long input** | Apply maximum lengths and reject excessive input without crashing. |
| **Special characters in input** | Use parameterized queries (`$1`, `$2`, ...) and avoid shell execution of user input. |

---

## 21. Docker Setup

### `Dockerfile`

```dockerfile
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/clilogin ./cmd/clilogin

FROM alpine:3.20
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
RUN mkdir -p /app/data && chown -R app:app /app
COPY --from=builder /out/clilogin /app/clilogin
USER app
ENTRYPOINT ["/app/clilogin"]
```

### `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: cli-postgres
    restart: unless-stopped
    command: ["postgres", "-p", "5430"]
    environment:
      POSTGRES_USER: ${DB_USER:-cli_user}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-cli_secret}
      POSTGRES_DB: ${DB_NAME:-cli_login_db}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5430:5430"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-cli_user} -d ${DB_NAME:-cli_login_db} -p 5430"]
      interval: 5s
      timeout: 5s
      retries: 5

  clilogin:
    build: .
    container_name: cli-login
    stdin_open: true
    tty: true
    depends_on:
      postgres:
        condition: service_healthy
    env_file:
      - .env
    environment:
      DB_HOST: postgres
      DB_PORT: 5430
      DB_USER: ${DB_USER:-cli_user}
      DB_PASSWORD: ${DB_PASSWORD:-cli_secret}
      DB_NAME: ${DB_NAME:-cli_login_db}
      DB_SSLMODE: disable
      READLINE_HISTORY_FILE: /app/data/.cli_history
    volumes:
      - cli_data:/app/data

volumes:
  postgres_data:
  cli_data:
```

The CLI is interactive, so `stdin_open` and `tty` are required. The `clilogin` service depends on `postgres` with `service_healthy` to guarantee database readiness before CLI launch. The named volume `postgres_data` preserves PostgreSQL database files across container restarts, and `cli_data` preserves readline history.

---

## 22. Main Startup Sequence

1. Load configuration from environment variables (`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSLMODE`, etc.).
2. Validate configuration values.
3. Create the data directory if needed (for readline history or QR temporary files).
4. Connect to PostgreSQL using connection pool (`*sql.DB`) with connection retry/backoff.
5. Verify connection using `db.PingContext(ctx)`.
6. Run migrations (`migrations/001_initial.sql`).
7. Construct repositories.
8. Construct `AuthService` with repositories and configuration.
9. Construct the readline shell.
10. Start the command loop.
11. On exit, revoke the current session if one exists, close readline, and close the database connection pool.

---

## 23. Testing Plan

- Registration creates a user with a bcrypt hash, not plaintext password.
- Duplicate usernames are rejected case-insensitively.
- Wrong password fails authentication.
- Successful login creates a session with the configured expiry.
- Session validation rejects expired sessions.
- Logout revokes a session.
- Failed attempts increase after wrong password.
- Account locks exactly at the configured threshold.
- Locked accounts remain locked across application restarts.
- Successful login resets `failed_attempts` and `locked_until`.
- TOTP enrollment is not persisted until the confirmation code is valid.
- Valid TOTP is accepted.
- Invalid TOTP is rejected.
- Previous-window TOTP is accepted when `Skew=1`.
- Disabling TOTP requires password and valid TOTP.
- Database persists when containers are restarted (`docker compose down` and `docker compose up`).
- CLI rejects commands that are not allowed in the current state.
- Ctrl+C and EOF close resources cleanly.

---

## 24. Implementation Order

1. Create the Go module and install dependencies (including `pgx/v5`).
2. Create configuration package and `.env.example`.
3. Create PostgreSQL connection pool with retry and migration runner.
4. Create models and repositories using `$1, $2, ...` placeholders.
5. Implement password hashing and input validation.
6. Implement registration.
7. Implement lockout tracking.
8. Implement session creation, validation, and revocation.
9. Implement password-only login.
10. Implement TOTP enrollment and validation.
11. Add authenticated commands: `whoami`, `logout`, `enable-2fa`, `disable-2fa`.
12. Add readline history and tab completion.
13. Add `Dockerfile` and multi-service `docker-compose.yml`.
14. Add unit and integration tests.
15. Write README with setup, commands, security decisions, and troubleshooting.
16. Perform a clean test from a fresh Docker build and verify PostgreSQL persistence.

---

## 25. README Requirements

The final README must contain:
- Project overview and feature list.
- Prerequisites: Docker and Docker Compose.
- How to copy `.env.example` to `.env`.
- How to build and start the multi-container environment: `docker compose up --build`.
- How to interact with the CLI.
- All unauthenticated and authenticated commands.
- How to scan the TOTP QR code.
- How session timeout and lockout settings work.
- How persistent PostgreSQL storage works (`postgres_data` volume).
- How to run tests.
- Security limitations, especially TOTP secret encryption and recovery-code absence.
- Known limitations and future improvements.

---

## 26. Deliberate Scope Limits

Do not add features that are not needed for the assignment unless the core requirements are complete. The following are outside the required scope:
- Password reset by email.
- Recovery codes.
- Multiple simultaneous sessions management UI.
- Admin user management.
- Remote API server.
- Distributed database.
- Sliding session expiration.
- Account deletion.

Recovery codes and encrypted TOTP-secret storage are good future improvements and should be mentioned in the README as limitations rather than left unexplained.

---

## 27. Final Acceptance Checklist

- [ ] `go test ./...` passes.
- [ ] A fresh user can register.
- [ ] The password is not visible during input.
- [ ] The password hash is stored in PostgreSQL.
- [ ] A user can log in and see the required profile/session details.
- [ ] A wrong password increments the failure counter.
- [ ] The account locks after five failed complete login attempts by default.
- [ ] A locked account cannot log in until the lock expires.
- [ ] A session expires according to `SESSION_TIMEOUT_MINUTES`.
- [ ] `whoami` fails after session expiry.
- [ ] `enable-2fa` produces a Google Authenticator-compatible QR code.
- [ ] A valid TOTP code enables MFA.
- [ ] Login requires TOTP after MFA is enabled.
- [ ] `disable-2fa` requires password and TOTP.
- [ ] `logout` revokes the session.
- [ ] `help` and tab completion work in both CLI states.
- [ ] Docker build succeeds.
- [ ] The application runs interactively inside Docker.
- [ ] The PostgreSQL database persists after `docker compose down` and `docker compose up`.
- [ ] README and migration files are included.

---

## 28. Reference Notes

The assignment requires the system to support optional TOTP-based 2FA, secure password storage, account lockout, session management, an interactive CLI, persistent database storage, Docker files, migrations, and documentation. This specification utilizes PostgreSQL 16 orchestrated via Docker Compose with health checks and volume persistence.

The selected TOTP library exposes `Generate`, `Validate`, and `ValidateCustom` functionality and supports a configurable period and skew window. A skew of one period allows verification against neighboring time steps; the server recalculates codes from the stored secret rather than storing previous codes.

---

*End of implementation specification*
