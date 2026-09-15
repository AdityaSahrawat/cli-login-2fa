package security

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid lowercase", "aditya", false},
		{"valid alphanumeric with dash", "user-123_test.ok", false},
		{"too short", "ab", true},
		{"too long", strings.Repeat("a", 33), true},
		{"invalid symbols", "user@host", true},
		{"spaces inside", "user name", true},
		{"surrounding spaces trimmed and valid", "  validuser  ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		pwd     string
		wantErr bool
	}{
		{"short password", "short123", true},
		{"11 chars", "12345678901", true},
		{"exact 12 chars", "123456789012", false},
		{"long password", "correct-horse-battery-staple-secure", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.pwd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.pwd, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePasswordConfirmation(t *testing.T) {
	if err := ValidatePasswordConfirmation("validpassword123", "validpassword123"); err != nil {
		t.Errorf("expected match, got error: %v", err)
	}
	if err := ValidatePasswordConfirmation("validpassword123", "mismatchpassword"); err == nil {
		t.Errorf("expected error on mismatch, got nil")
	}
}

func TestValidateTOTPCode(t *testing.T) {
	if err := ValidateTOTPCode("123456"); err != nil {
		t.Errorf("expected valid 6-digit code, got %v", err)
	}
	if err := ValidateTOTPCode("12345"); err == nil {
		t.Errorf("expected error for 5 digits, got nil")
	}
	if err := ValidateTOTPCode("1234567"); err == nil {
		t.Errorf("expected error for 7 digits, got nil")
	}
	if err := ValidateTOTPCode("12a456"); err == nil {
		t.Errorf("expected error for non-digit characters, got nil")
	}
}

func TestAES256GCMEncryption(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := "JBSWY3DPEHPK3PXP" // example base32 TOTP secret

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if encrypted == plaintext {
		t.Errorf("ciphertext should not match plaintext")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}

	// Wrong key should fail decryption
	wrongKey := make([]byte, 32)
	wrongKey[0] = ^key[0]
	if _, err := Decrypt(encrypted, wrongKey); err == nil {
		t.Errorf("expected decryption failure with wrong key, got nil")
	}
}

func TestSessionTokenGeneration(t *testing.T) {
	t1, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("token generation failed: %v", err)
	}
	t2, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("token generation failed: %v", err)
	}
	if t1 == t2 {
		t.Errorf("tokens must be unique")
	}

	h1 := HashToken(t1)
	h2 := HashToken(t1)
	if h1 != h2 {
		t.Errorf("hashing must be deterministic")
	}
}
