# Containerized CLI Login System with PostgreSQL & 2FA

A secure, interactive command-line authentication system built with **Go**, **PostgreSQL 16**, **Docker Compose**, and optional **TOTP-based Two-Factor Authentication (Google Authenticator)**.

---

## Table of Contents

- [Features](#features)
- [Project Architecture & Directory Structure](#project-architecture--directory-structure)
  - [File Responsibilities](#file-responsibilities)
- [Getting Started with Docker Compose](#getting-started-with-docker-compose)
  - [Prerequisites](#prerequisites)
  - [1. Configure Environment](#1-configure-environment)
  - [2. Build and Start the Stack](#2-build-and-start-the-stack)
  - [3. Attached Interactive Session](#3-attached-interactive-session)
- [Command Reference](#command-reference)
  - [Unauthenticated State](#unauthenticated-state)
  - [Authenticated State](#authenticated-state)
- [Step-by-Step Walkthrough](#step-by-step-walkthrough)
  - [1. User Registration (`register`)](#1-user-registration-register)
  - [2. User Login (`login`)](#2-user-login-login)
  - [3. Profile & Session Info (`whoami`)](#3-profile--session-info-whoami)
  - [4. Enabling 2FA (`enable-2fa`)](#4-enabling-2fa-enable-2fa)
  - [5. Logging in with 2FA](#5-logging-in-with-2fa)
  - [6. Disabling 2FA (`disable-2fa`)](#6-disabling-2fa-disable-2fa)
  - [7. Logging Out (`logout`)](#7-logging-out-logout)
- [Deep Dive: Security Features](#deep-dive-security-features)
  - [Account Lockout Mechanism](#account-lockout-mechanism)
  - [Session Management & Configurable Timeout](#session-management--configurable-timeout)
  - [TOTP Secret Encryption at Rest (AES-256-GCM)](#totp-secret-encryption-at-rest-aes-256-gcm)
  - [Password Hashing & Timing Attack Mitigation](#password-hashing--timing-attack-mitigation)
- [Running Tests](#running-tests)
- [Configuration Reference](#configuration-reference)

---

## Features

- **Robust Persistence:** PostgreSQL 16 database running via Docker Compose with volume-backed persistence.
- **Strict Password Security:** Passwords hashed with `bcrypt` (configurable cost); input is fully masked in the terminal.
- **Account Lockout Protection:** Automatically locks an account after 5 consecutive failed attempts for 15 minutes (configurable), resisting brute-force attacks.
- **Optional TOTP 2FA:** Compatible with Google Authenticator, 1Password, Authy; generates dual output:
  - High-contrast ANSI block QR code rendered directly in your terminal.
  - Optional `.png` QR image saved to the shared data volume.
- **Encrypted Secrets at Rest:** TOTP secrets encrypted with AES-256-GCM before database insertion.
- **Session Management:** Secure 32-byte tokens (`crypto/rand`) stored as SHA-256 hashes in PostgreSQL with absolute timeouts.
- **Interactive Shell:** Tab auto-completion, command history file persistence, and dynamic state-aware prompts (`cli-login> ` vs `cli-login(username)> `).

---

## Project Architecture & Directory Structure

```text
cli-login-2fa/
├── cmd/
│   └── clilogin/
│       └── main.go              # Application entrypoint & signal handler
├── internal/
│   ├── app/
│   │   └── app.go               # Dependency injection container & lifecycle
│   ├── auth/
│   │   ├── service.go           # Core AuthService implementation
│   │   ├── password.go          # Bcrypt hashing & timing attack defense
│   │   ├── lockout.go           # Account lockout rules & checks
│   │   ├── session.go           # Session validity & expiration evaluation
│   │   ├── totp.go              # TOTP key generation & dual QR rendering
│   │   └── auth_test.go         # Complete unit test suite for auth flows
│   ├── cli/
│   │   ├── shell.go             # Readline interactive command loop & completer
│   │   ├── commands.go          # Handlers for all CLI commands
│   │   ├── prompts.go           # Hidden password & interactive input reader
│   │   └── output.go            # Standardized user-facing message printer
│   ├── config/
│   │   ├── config.go            # Environment loader & strict validator
│   │   └── config_test.go       # Config validation tests
│   ├── database/
│   │   ├── db.go                # PostgreSQL connection pool with retry ping
│   │   ├── migrations.go        # Schema migration runner with schema_migrations table
│   │   └── repositories.go      # Parameterized ($1, $2) PostgreSQL queries
│   ├── models/
│   │   └── models.go            # User, Session, and Enrollment structs
│   └── security/
│       ├── random.go            # Cryptographic random generator & token hasher
│       ├── sanitize.go          # Input normalization & validation regex
│       ├── encrypt.go           # AES-256-GCM encryption for TOTP secrets
│       └── security_test.go     # Security & encryption unit tests
├── migrations/
│   ├── 001_initial.sql          # Citext extension, users & sessions tables, indexes
│   └── migrations.go            # Embeds SQL files into Go binary via embed.FS
├── tests/
│   └── integration_test.go      # PostgreSQL database integration tests
├── data/
│   └── .gitkeep                 # Shared directory for readline history & QR PNGs
├── Dockerfile                   # Multi-stage container build (Alpine runtime)
├── docker-compose.yml           # PostgreSQL + CLI multi-service setup
├── go.mod                       # Go module & dependency declarations
├── go.sum                       # Cryptographic dependency checksums
├── .env.example                 # Template for required environment settings
├── .gitignore                   # Ignores .env, binaries, and runtime artifacts
└── README.md                    # Project documentation
```

### File Responsibilities

| File | Purpose |
| --- | --- |
| `cmd/clilogin/main.go` | Entrypoint: loads config, hooks OS shutdown signals (`SIGINT`/`SIGTERM`), and starts `App`. |
| `internal/app/app.go` | Wires PostgreSQL connection pool, runs migrations, constructs repositories and services, and runs readline shell. |
| `internal/config/config.go` | Reads and strictly validates environment variables; fails early if `ENCRYPTION_KEY` is missing. |
| `internal/database/db.go` | Opens `pgx` connection pool (`*sql.DB`) and executes retry backoff (up to 30s) waiting for PostgreSQL readiness. |
| `internal/database/migrations.go` | Applies migrations in version order within transactions; tracks applied versions in `schema_migrations`. |
| `internal/database/repositories.go` | Contains all parameterized PostgreSQL queries (`$1, $2, ...`) for users and sessions. |
| `internal/auth/service.go` | Business logic for registration, password verification, lockout evaluation, MFA enrollment, and sessions. |
| `internal/auth/password.go` | Bcrypt password hashing (`bcrypt.GenerateFromPassword`) and dummy comparison for unknown users. |
| `internal/auth/lockout.go` | Atomic counter increments and expiration checks for temporarily locked accounts. |
| `internal/auth/session.go` | Absolute expiration and revocation checks for active sessions. |
| `internal/auth/totp.go` | TOTP key generation, validation with clock skew (`Skew=1`), terminal ANSI QR and PNG export. |
| `internal/security/encrypt.go` | AES-256-GCM encryption/decryption for TOTP secrets stored in the database. |
| `internal/security/sanitize.go` | Input sanitization, password length check (min 12), username regex (`^[a-zA-Z0-9_.-]{3,32}$`). |
| `internal/security/random.go` | Cryptographically secure random token generation (`crypto/rand`) and SHA-256 token hashing. |
| `internal/cli/shell.go` | Interactive readline loop, state-aware tab completion, and dynamic command prompts. |
| `internal/cli/commands.go` | Dispatches user commands and formats profile/session outputs. |
| `internal/cli/prompts.go` | Reads user inputs with terminal password masking (hidden echo). |

---

## Getting Started with Docker Compose

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v20.10+)
- [Docker Compose](https://docs.docker.com/compose/) (v2.0+)

### 1. Configure Environment

Copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

Ensure `ENCRYPTION_KEY` is set to a 64-character hex string (32 bytes). You can generate a fresh one anytime with:
```bash
openssl rand -hex 32
```

### 2. Build and Start the Stack

To build and run the services in the background:

```bash
docker compose up --build -d
```

This starts:
1. **`postgres`**: PostgreSQL 16 with a persistent Docker volume (`postgres_data`).
2. **`clilogin`**: Waiting on PostgreSQL healthcheck (`pg_isready`) before launching.

### 3. Attached Interactive Session

Because the CLI is an interactive console application requiring `stdin` and a `tty`, connect to the running interactive container:

```bash
docker compose run --rm clilogin
```

Alternatively, if you run `docker compose up` directly without `-d`, you can interact immediately in your terminal!

To stop the containers:
```bash
docker compose down
```
*(Note: Your database data and history persist in `postgres_data` and `cli_data` volumes across restarts.)*

---

## Command Reference

### Unauthenticated State

When you first start the application, you are unauthenticated. The prompt displays: `cli-login> `.

| Command | Description |
| --- | --- |
| `register` | Create a new user account |
| `login` | Authenticate with username, password, and optional TOTP code |
| `help` | Show commands available in the unauthenticated state |
| `exit` | Exit the CLI application cleanly |

### Authenticated State

Once logged in, the prompt changes to reflect your username: `cli-login(<username>)> `.

| Command | Description |
| --- | --- |
| `whoami` | Display details about the current user and active session |
| `enable-2fa` | Enroll in TOTP two-factor authentication (Google Authenticator) |
| `disable-2fa` | Disable TOTP two-factor authentication (requires password + code) |
| `logout` | Revoke the active session and return to unauthenticated state |
| `help` | Show commands available in the authenticated state |
| `exit` | Revoke the current session and terminate the CLI |

---

## Step-by-Step Walkthrough

### 1. User Registration (`register`)

Type `register` and press Enter. Enter a username (3–32 characters) and password (minimum 12 characters). Passwords are masked as you type.

```text
cli-login> register
Username: aditya
Password: 
Confirm password: 
Registration successful.
```

**Rules:**
- Username is case-insensitive (e.g. `Aditya` and `aditya` point to the same account).
- Passwords must be at least 12 characters.
- Passwords must match the confirmation.

---

### 2. User Login (`login`)

Authenticate with your registered credentials:

```text
cli-login> login
Username: aditya
Password: 

Login successful.
Username: aditya
Registration date: 2026-09-15T15:30:00Z
MFA status: disabled
Session expires: 2026-09-15T16:00:00Z
Last login: First login

cli-login(aditya)> 
```

Notice that the prompt dynamically transitions to `cli-login(aditya)> `.

---

### 3. Profile & Session Info (`whoami`)

Run `whoami` to inspect your active session:

```text
cli-login(aditya)> whoami
Username: aditya
Registration date: 2026-09-15T15:30:00Z
MFA status: disabled
Session expires: 2026-09-15T16:00:00Z
Last login: 2026-09-15T15:35:12Z
```

---

### 4. Enabling 2FA (`enable-2fa`)

Run `enable-2fa` to begin TOTP enrollment. The application renders an ANSI QR code directly in the terminal:

```text
cli-login(aditya)> enable-2fa
A QR code has been generated. Scan it with Google Authenticator:

▄▄▄▄▄▄▄ ▄▄  ▄▄ ▄▄▄▄▄▄▄
█ ▄▄▄ █ █ █ ▄█ █ ▄▄▄ █
█ ███ █ ▄█▄ ▀█ █ ███ █
█▄▄▄▄▄█ ▄ ▄▀ █ █▄▄▄▄▄█
... [QR code renders here] ...

QR code image saved to: /app/data/totp-aditya.png
Enter the 6-digit code to confirm: 481920
2FA enabled successfully.
```

**How enrollment works:**
1. The TOTP secret is generated **only in memory**.
2. You scan the QR code using Google Authenticator, 1Password, or Authy.
3. You enter the 6-digit code displayed on your app.
4. The system validates the code. Only after validation succeeds is the secret encrypted with AES-256-GCM and committed to PostgreSQL.

---

### 5. Logging in with 2FA

When 2FA is enabled, logging in asks for your TOTP code after password verification:

```text
cli-login> login
Username: aditya
Password: 
TOTP code (if enabled): 481920

Login successful.
Username: aditya
Registration date: 2026-09-15T15:30:00Z
MFA status: enabled
Session expires: 2026-09-15T16:30:00Z
Last login: 2026-09-15T15:40:00Z

cli-login(aditya)> 
```

---

### 6. Disabling 2FA (`disable-2fa`)

To disable 2FA, you must provide **both** your current password and a valid TOTP code to prevent accidental or unauthorized disabling:

```text
cli-login(aditya)> disable-2fa
Enter current password: 
Enter current TOTP code: 719283
2FA disabled successfully.
```

---

### 7. Logging Out (`logout`)

Explicitly end your active session:

```text
cli-login(aditya)> logout
Logged out successfully.
cli-login> 
```

The database immediately marks the session as revoked, and the in-memory token is cleared.

---

## Deep Dive: Security Features

### Account Lockout Mechanism

To protect user accounts from automated credential stuffing and brute-force dictionary attacks, the system implements a strict lockout policy:

1. **Failure Threshold (`MAX_FAILED_ATTEMPTS`):** Defaults to `5`.
2. **Lock Duration (`LOCKOUT_MINUTES`):** Defaults to `15` minutes.
3. **What Counts as a Failed Attempt:**
   - Entering an incorrect password.
   - Entering an incorrect TOTP code when 2FA is enabled.
4. **Lockout Check Before Password Check:**
   - If an account is currently locked, the login request is immediately rejected with `Account temporarily locked. Try again later.` without verifying the password.
   - Entering a correct password while locked does **not** bypass the lock.
5. **Automatic Lock Expiry:**
   - Once the lockout duration has elapsed, the next login attempt automatically resets the failure counter and clears the lock.
6. **Timing Attack Protection (`DummyCompare`):**
   - If an attacker attempts to log in with a non-existent username, the system performs a dummy `bcrypt` computation with the same cost factor. This ensures responses for existing and non-existing users take identical processing time, preventing username enumeration through timing analysis.

### Session Management & Configurable Timeout

1. **Token Generation:**
   - Upon successful login, 32 cryptographically secure random bytes are generated via `crypto/rand`.
   - The token is base64-URL encoded and kept **only in process memory**.
2. **Hashing at Rest:**
   - The token is hashed with SHA-256 before being inserted into PostgreSQL.
   - Even if the database were compromised, raw session tokens cannot be recovered.
3. **Absolute Expiration (`SESSION_TIMEOUT_MINUTES`):**
   - Configurable timeout (default: `30` minutes).
   - The expiration is **absolute**, not sliding: executing commands does not extend the session. Once the timestamp is passed, the CLI terminates the session and returns to the unauthenticated prompt:
     `Session expired. Please log in again.`
4. **Immediate Revocation:**
   - Calling `logout` or `exit` sets `revoked_at = NOW()` in the database and clears the in-memory token.

### TOTP Secret Encryption at Rest (AES-256-GCM)

A TOTP secret cannot be stored as a one-way hash because the server must calculate valid codes for incoming time steps. Storing plaintext secrets in a database is a significant vulnerability.

- **Implementation:** The application implements AES-256-GCM encryption in `internal/security/encrypt.go`.
- **Key Requirement:** A 256-bit (32-byte) key is provided via `ENCRYPTION_KEY`.
- **Initialization Vector:** A unique 12-byte cryptographic nonce is generated for every encryption operation and prepended to the ciphertext.
- **Integrity Tag:** AES-GCM guarantees both confidentiality and data authenticity; any tampering or wrong key causes immediate decryption failure.

### Password Hashing & Timing Attack Mitigation

- **Algorithm:** `bcrypt` (`golang.org/x/crypto/bcrypt`) with configurable cost (default: `12`).
- **Policy:** Enforces a 12-character minimum length.
- **Masking:** Passwords are never echoed back to stdout, never written to disk, and never output in application logs.

---

## Running Tests

All unit tests are decoupled from external services using in-memory mock repositories and can be run instantly on any machine:

```bash
go test -v ./...
```

### Running Integration Tests with Live PostgreSQL

1. Start PostgreSQL using Docker Compose:
   ```bash
   docker compose up -d postgres
   ```
2. Run tests against the live database:
   ```bash
   go test -v ./tests/...
   ```
   *(If PostgreSQL is not running, the integration tests will gracefully report via `t.Skip` without failing the test suite).*

---

## Configuration Reference

The application reads configuration from environment variables (or `.env`):

| Variable | Default | Description |
| --- | --- | --- |
| `APP_NAME` | `cli-login` | Application identifier |
| `DB_HOST` | `postgres` | PostgreSQL hostname / container name |
| `DB_PORT` | `5430` | PostgreSQL listening port |
| `DB_USER` | `cli_user` | PostgreSQL database user |
| `DB_PASSWORD` | `cli_secret` | PostgreSQL database password |
| `DB_NAME` | `cli_login_db` | PostgreSQL database name |
| `DB_SSLMODE` | `disable` | PostgreSQL SSL connection mode |
| `DB_MAX_OPEN_CONNS` | `10` | Maximum open database connections |
| `DB_MAX_IDLE_CONNS` | `5` | Maximum idle database connections |
| `SESSION_TIMEOUT_MINUTES` | `30` | Absolute duration before a session expires |
| `MAX_FAILED_ATTEMPTS` | `5` | Failed logins before account is locked |
| `LOCKOUT_MINUTES` | `15` | Duration of account lockout |
| `BCRYPT_COST` | `12` | Bcrypt hashing work factor (4–31) |
| `TOTP_PERIOD_SECONDS` | `30` | Time step for TOTP codes |
| `TOTP_SKEW_PERIODS` | `1` | Permitted clock-skew periods (previous, current, next) |
| `TOTP_ISSUER` | `CLI Login` | Issuer label displayed in Authenticator apps |
| `READLINE_HISTORY_FILE` | `/app/data/.cli_history` | File path for persistent command history |
| `ENCRYPTION_KEY` | *(Required)* | 32-byte hex/raw key for AES-256-GCM encryption |