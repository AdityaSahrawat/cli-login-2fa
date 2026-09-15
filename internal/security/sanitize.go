package security

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// usernameRegex permits letters, digits, underscore, hyphen, and period; 3 to 32 chars.
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)

	ErrInvalidUsernameLength = errors.New("username must be between 3 and 32 characters")
	ErrInvalidUsernameChars  = errors.New("username can only contain letters, numbers, underscores, hyphens, and periods")
	ErrPasswordTooShort      = errors.New("password must be at least 12 characters")
	ErrPasswordMismatch      = errors.New("password confirmation does not match")
	ErrInvalidTOTPCode       = errors.New("verification code must be exactly 6 digits")
)

// NormalizeUsername trims leading and trailing whitespace from a username.
func NormalizeUsername(u string) string {
	return strings.TrimSpace(u)
}

// ValidateUsername checks if the username meets format and length rules.
func ValidateUsername(username string) error {
	trimmed := NormalizeUsername(username)
	if len(trimmed) < 3 || len(trimmed) > 32 {
		return ErrInvalidUsernameLength
	}
	if !usernameRegex.MatchString(trimmed) {
		return ErrInvalidUsernameChars
	}
	return nil
}

// ValidatePassword checks if the password meets minimum security rules.
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return ErrPasswordTooShort
	}
	return nil
}

// ValidatePasswordConfirmation checks if password and confirmation match.
func ValidatePasswordConfirmation(password, confirm string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	if password != confirm {
		return ErrPasswordMismatch
	}
	return nil
}

// ValidateTOTPCode validates that the submitted TOTP code is exactly 6 numeric digits.
func ValidateTOTPCode(code string) error {
	trimmed := strings.TrimSpace(code)
	if len(trimmed) != 6 {
		return ErrInvalidTOTPCode
	}
	for _, ch := range trimmed {
		if ch < '0' || ch > '9' {
			return ErrInvalidTOTPCode
		}
	}
	return nil
}
