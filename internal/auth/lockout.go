package auth

import (
	"time"

	"cli-login/internal/models"
)

// IsLocked checks if the account is currently locked out at the given time.
func IsLocked(u *models.User, now time.Time) bool {
	if u.LockedUntil == nil {
		return false
	}
	return now.UTC().Before(u.LockedUntil.UTC())
}

// IsLockExpired checks if the user has a locked_until timestamp that has already elapsed.
func IsLockExpired(u *models.User, now time.Time) bool {
	if u.LockedUntil == nil {
		return false
	}
	return !now.UTC().Before(u.LockedUntil.UTC())
}
