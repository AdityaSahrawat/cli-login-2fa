package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"cli-login/internal/models"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrSessionNotFound   = errors.New("session not found")
	ErrDuplicateUsername = errors.New("username is already unavailable")
)

// UserRepository defines database operations for users.
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByUsername(ctx context.Context, username string) (*models.User, error)
	FindByID(ctx context.Context, id int64) (*models.User, error)
	RecordFailedLogin(ctx context.Context, userID int64, now time.Time, maxAttempts int, lockDuration time.Duration) error
	ResetLoginFailures(ctx context.Context, userID int64, now time.Time) error
	UpdateTOTP(ctx context.Context, userID int64, enabled bool, secret *string) error
}

// SessionRepository defines database operations for sessions.
type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error)
	Revoke(ctx context.Context, tokenHash string, now time.Time) error
}

// PostgresUserRepository implements UserRepository with PostgreSQL.
type PostgresUserRepository struct {
	db *sql.DB
}

// NewPostgresUserRepository returns a new PostgresUserRepository.
func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Create(ctx context.Context, u *models.User) error {
	query := `
		INSERT INTO users (username, password_hash, registered_at, failed_attempts, totp_enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id;`

	err := r.db.QueryRowContext(ctx, query,
		u.Username,
		u.PasswordHash,
		u.RegisteredAt.UTC(),
		u.FailedAttempts,
		u.TOTPEnabled,
	).Scan(&u.ID)

	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate key") {
			return ErrDuplicateUsername
		}
		return err
	}
	return nil
}

func (r *PostgresUserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, registered_at, last_login_at, failed_attempts, locked_until, totp_enabled, totp_secret
		FROM users
		WHERE username = $1;`

	u := &models.User{}
	var lastLogin sql.NullTime
	var lockedUntil sql.NullTime
	var secret sql.NullString

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.RegisteredAt,
		&lastLogin,
		&u.FailedAttempts,
		&lockedUntil,
		&u.TOTPEnabled,
		&secret,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if lastLogin.Valid {
		t := lastLogin.Time.UTC()
		u.LastLoginAt = &t
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time.UTC()
		u.LockedUntil = &t
	}
	if secret.Valid {
		s := secret.String
		u.TOTPSecret = &s
	}

	return u, nil
}

func (r *PostgresUserRepository) FindByID(ctx context.Context, id int64) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, registered_at, last_login_at, failed_attempts, locked_until, totp_enabled, totp_secret
		FROM users
		WHERE id = $1;`

	u := &models.User{}
	var lastLogin sql.NullTime
	var lockedUntil sql.NullTime
	var secret sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.RegisteredAt,
		&lastLogin,
		&u.FailedAttempts,
		&lockedUntil,
		&u.TOTPEnabled,
		&secret,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if lastLogin.Valid {
		t := lastLogin.Time.UTC()
		u.LastLoginAt = &t
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time.UTC()
		u.LockedUntil = &t
	}
	if secret.Valid {
		s := secret.String
		u.TOTPSecret = &s
	}

	return u, nil
}

func (r *PostgresUserRepository) RecordFailedLogin(ctx context.Context, userID int64, now time.Time, maxAttempts int, lockDuration time.Duration) error {
	lockUntil := now.Add(lockDuration).UTC()
	query := `
		UPDATE users
		SET failed_attempts = failed_attempts + 1,
		    locked_until = CASE
		        WHEN failed_attempts + 1 >= $2 THEN $3
		        ELSE locked_until
		    END
		WHERE id = $1;`

	_, err := r.db.ExecContext(ctx, query, userID, maxAttempts, lockUntil)
	return err
}

func (r *PostgresUserRepository) ResetLoginFailures(ctx context.Context, userID int64, now time.Time) error {
	query := `
		UPDATE users
		SET failed_attempts = 0,
		    locked_until = NULL,
		    last_login_at = $2
		WHERE id = $1;`

	_, err := r.db.ExecContext(ctx, query, userID, now.UTC())
	return err
}

func (r *PostgresUserRepository) UpdateTOTP(ctx context.Context, userID int64, enabled bool, secret *string) error {
	query := `
		UPDATE users
		SET totp_enabled = $2,
		    totp_secret = $3
		WHERE id = $1;`

	var secParam sql.NullString
	if secret != nil {
		secParam = sql.NullString{String: *secret, Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query, userID, enabled, secParam)
	return err
}

// PostgresSessionRepository implements SessionRepository with PostgreSQL.
type PostgresSessionRepository struct {
	db *sql.DB
}

// NewPostgresSessionRepository returns a new PostgresSessionRepository.
func NewPostgresSessionRepository(db *sql.DB) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, s *models.Session) error {
	query := `
		INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id;`

	err := r.db.QueryRowContext(ctx, query,
		s.UserID,
		s.TokenHash,
		s.CreatedAt.UTC(),
		s.ExpiresAt.UTC(),
	).Scan(&s.ID)

	return err
}

func (r *PostgresSessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	query := `
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = $1;`

	s := &models.Session{}
	var revoked sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&s.ID,
		&s.UserID,
		&s.TokenHash,
		&s.CreatedAt,
		&s.ExpiresAt,
		&revoked,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	if revoked.Valid {
		t := revoked.Time.UTC()
		s.RevokedAt = &t
	}

	return s, nil
}

func (r *PostgresSessionRepository) Revoke(ctx context.Context, tokenHash string, now time.Time) error {
	query := `
		UPDATE sessions
		SET revoked_at = $2
		WHERE token_hash = $1 AND revoked_at IS NULL;`

	_, err := r.db.ExecContext(ctx, query, tokenHash, now.UTC())
	return err
}
