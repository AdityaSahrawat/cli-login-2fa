package auth

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plain text password using bcrypt with the given cost.
func HashPassword(password string, cost int) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ComparePassword compares a bcrypt hashed password with its possible plaintext equivalent.
func ComparePassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// DummyCompare performs a dummy bcrypt comparison to reduce timing side-channel differences
// when a requested username does not exist.
func DummyCompare(cost int) {
	// A fixed valid bcrypt hash (cost 12 for "dummy-password")
	dummyHash := "$2a$12$e8Y5tG5gqB8bZfJ3l1w2oe4UjD9q.Oq4h9dC.T5c3s9e3p1v1q1v1"
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte("dummy-password"))
}
