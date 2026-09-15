package auth

import (
	"time"

	"cli-login/internal/models"
)

// IsSessionExpired checks if the session has reached its absolute expiration time.
func IsSessionExpired(s *models.Session, now time.Time) bool {
	return !now.UTC().Before(s.ExpiresAt.UTC())
}

// IsSessionRevoked checks if the session has been revoked.
func IsSessionRevoked(s *models.Session) bool {
	return s.RevokedAt != nil
}

// IsSessionValid returns true if the session exists, is not revoked, and has not expired.
func IsSessionValid(s *models.Session, now time.Time) bool {
	if s == nil {
		return false
	}
	if IsSessionRevoked(s) {
		return false
	}
	if IsSessionExpired(s, now) {
		return false
	}
	return true
}
