package models

import "time"

// User represents a user record stored in the database.
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

// Session represents a session record stored in the database.
type Session struct {
	ID        int64
	UserID    int64
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// AuthenticatedSession represents the in-memory state of an active session.
type AuthenticatedSession struct {
	UserID    int64
	Username  string
	Token     string
	ExpiresAt time.Time
}

// TOTPEnrollment holds temporary details during TOTP setup before confirmation.
type TOTPEnrollment struct {
	Secret  string
	QRPath  string
	Issuer  string
	Account string
}
