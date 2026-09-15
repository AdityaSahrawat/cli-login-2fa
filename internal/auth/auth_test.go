package auth

import (
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"cli-login/internal/config"
	"cli-login/internal/database"
	"cli-login/internal/models"

	"github.com/pquerna/otp/totp"
)

// In-memory mock repositories
type mockUserRepo struct {
	mu    sync.Mutex
	users map[string]*models.User // keyed by lower(username)
	seq   int64
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users: make(map[string]*models.User),
	}
}

func (m *mockUserRepo) Create(ctx context.Context, u *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(u.Username)
	if _, exists := m.users[key]; exists {
		return database.ErrDuplicateUsername
	}

	m.seq++
	u.ID = m.seq
	copyUser := *u
	m.users[key] = &copyUser
	return nil
}

func (m *mockUserRepo) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(username)
	u, exists := m.users[key]
	if !exists {
		return nil, database.ErrUserNotFound
	}
	copyUser := *u
	return &copyUser, nil
}

func (m *mockUserRepo) FindByID(ctx context.Context, id int64) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, u := range m.users {
		if u.ID == id {
			copyUser := *u
			return &copyUser, nil
		}
	}
	return nil, database.ErrUserNotFound
}

func (m *mockUserRepo) RecordFailedLogin(ctx context.Context, userID int64, now time.Time, maxAttempts int, lockDuration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, u := range m.users {
		if u.ID == userID {
			u.FailedAttempts++
			if u.FailedAttempts >= maxAttempts {
				lockUntil := now.Add(lockDuration).UTC()
				u.LockedUntil = &lockUntil
			}
			m.users[key] = u
			return nil
		}
	}
	return database.ErrUserNotFound
}

func (m *mockUserRepo) ResetLoginFailures(ctx context.Context, userID int64, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, u := range m.users {
		if u.ID == userID {
			u.FailedAttempts = 0
			u.LockedUntil = nil
			t := now.UTC()
			u.LastLoginAt = &t
			m.users[key] = u
			return nil
		}
	}
	return database.ErrUserNotFound
}

func (m *mockUserRepo) UpdateTOTP(ctx context.Context, userID int64, enabled bool, secret *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, u := range m.users {
		if u.ID == userID {
			u.TOTPEnabled = enabled
			u.TOTPSecret = secret
			m.users[key] = u
			return nil
		}
	}
	return database.ErrUserNotFound
}

type mockSessionRepo struct {
	mu       sync.Mutex
	sessions map[string]*models.Session
	seq      int64
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions: make(map[string]*models.Session),
	}
}

func (m *mockSessionRepo) Create(ctx context.Context, s *models.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq++
	s.ID = m.seq
	copySess := *s
	m.sessions[s.TokenHash] = &copySess
	return nil
}

func (m *mockSessionRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, exists := m.sessions[tokenHash]
	if !exists {
		return nil, database.ErrSessionNotFound
	}
	copySess := *s
	return &copySess, nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, tokenHash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, exists := m.sessions[tokenHash]; exists {
		t := now.UTC()
		s.RevokedAt = &t
	}
	return nil
}

func testConfig() *config.Config {
	key := make([]byte, 32)
	rand.Read(key)
	return &config.Config{
		AppName:               "cli-login",
		SessionTimeoutMinutes: 30,
		MaxFailedAttempts:     5,
		LockoutMinutes:        15,
		BcryptCost:            4, // fast cost for unit tests
		TOTPPeriodSeconds:     30,
		TOTPSkewPeriods:       1,
		TOTPIssuer:            "CLI Login",
		ReadlineHistoryFile:   "/tmp/.cli_history",
		EncryptionKey:         key,
	}
}

func TestRegisterAndLoginFlow(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()
	uRepo := newMockUserRepo()
	sRepo := newMockSessionRepo()
	svc := NewService(cfg, uRepo, sRepo)

	// 1. Register valid user
	err := svc.Register(ctx, "aditya", "valid_password_123", "valid_password_123")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// 2. Duplicate registration case-insensitively
	err = svc.Register(ctx, "ADITYA", "valid_password_123", "valid_password_123")
	if err == nil {
		t.Errorf("expected duplicate username error, got nil")
	}

	// 3. Password mismatch
	err = svc.Register(ctx, "aditya2", "valid_password_123", "wrong_confirm_123")
	if err == nil {
		t.Errorf("expected mismatch error, got nil")
	}

	// 4. Login with wrong password
	_, err = svc.Login(ctx, "aditya", "wrong_password_123", "")
	if err == nil || err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// 5. Successful login
	sess, err := svc.Login(ctx, "aditya", "valid_password_123", "")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if sess.Username != "aditya" || sess.Token == "" {
		t.Errorf("invalid session returned: %+v", sess)
	}

	// 6. GetCurrentUser
	user, session, err := svc.GetCurrentUser(ctx, sess.Token)
	if err != nil {
		t.Fatalf("GetCurrentUser failed: %v", err)
	}
	if user.Username != "aditya" {
		t.Errorf("expected username aditya, got %s", user.Username)
	}
	if user.PasswordHash != "" {
		t.Errorf("password hash must never be returned in user profile")
	}
	if session == nil {
		t.Fatalf("session is nil")
	}

	// 7. Logout revokes session
	err = svc.Logout(ctx, sess.Token)
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	_, _, err = svc.GetCurrentUser(ctx, sess.Token)
	if err == nil {
		t.Errorf("expected error after logout, got nil")
	}
}

func TestAccountLockout(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()
	uRepo := newMockUserRepo()
	sRepo := newMockSessionRepo()
	svc := NewService(cfg, uRepo, sRepo)

	_ = svc.Register(ctx, "lockuser", "valid_password_123", "valid_password_123")

	// Fail 4 times - account should still be unlocked
	for i := 1; i <= 4; i++ {
		_, err := svc.Login(ctx, "lockuser", "wrongpwd12345", "")
		if err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}

	// 5th failure triggers lockout
	_, err := svc.Login(ctx, "lockuser", "wrongpwd12345", "")
	if err != ErrInvalidCredentials {
		t.Fatalf("attempt 5: expected ErrInvalidCredentials, got %v", err)
	}

	// 6th attempt with correct password must be rejected because account is locked!
	_, err = svc.Login(ctx, "lockuser", "valid_password_123", "")
	if err != ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
}

func TestTOTPEnrollmentFlow(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()
	uRepo := newMockUserRepo()
	sRepo := newMockSessionRepo()
	svc := NewService(cfg, uRepo, sRepo)

	_ = svc.Register(ctx, "totpuser", "valid_password_123", "valid_password_123")
	sess, err := svc.Login(ctx, "totpuser", "valid_password_123", "")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Begin TOTP enrollment
	enrollment, err := svc.BeginTOTPEnrollment(ctx, sess.Token)
	if err != nil {
		t.Fatalf("BeginTOTPEnrollment failed: %v", err)
	}
	if enrollment.Secret == "" {
		t.Fatalf("enrollment secret is empty")
	}

	// Check DB: secret must NOT be in database yet!
	dbUser, _ := uRepo.FindByUsername(ctx, "totpuser")
	if dbUser.TOTPEnabled || dbUser.TOTPSecret != nil {
		t.Errorf("TOTP secret must not be persisted before confirmation")
	}

	// Invalid confirmation code
	err = svc.ConfirmTOTPEnrollment(ctx, sess.Token, "000000", enrollment)
	if err == nil {
		t.Errorf("expected error on invalid code, got nil")
	}

	// Generate valid code for the secret at current time
	code, err := totp.GenerateCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	// Confirm enrollment
	err = svc.ConfirmTOTPEnrollment(ctx, sess.Token, code, enrollment)
	if err != nil {
		t.Fatalf("ConfirmTOTPEnrollment failed: %v", err)
	}

	// User should now have TOTP enabled and encrypted secret in DB
	dbUser, _ = uRepo.FindByUsername(ctx, "totpuser")
	if !dbUser.TOTPEnabled || dbUser.TOTPSecret == nil {
		t.Fatalf("TOTP should be enabled after confirmation")
	}

	// Logging in without TOTP code must return ErrTOTPRequired
	_, err = svc.Login(ctx, "totpuser", "valid_password_123", "")
	if err != ErrTOTPRequired {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}

	// Logging in with wrong TOTP code must fail
	_, err = svc.Login(ctx, "totpuser", "valid_password_123", "000000")
	if err != ErrInvalidTOTP {
		t.Fatalf("expected ErrInvalidTOTP, got %v", err)
	}

	// Logging in with valid TOTP code
	newCode, _ := totp.GenerateCode(enrollment.Secret, time.Now().UTC())
	newSess, err := svc.Login(ctx, "totpuser", "valid_password_123", newCode)
	if err != nil {
		t.Fatalf("login with TOTP failed: %v", err)
	}

	// Disable 2FA with wrong password
	err = svc.DisableTOTP(ctx, newSess.Token, "wrongpassword", newCode)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// Disable 2FA with valid password and valid code
	disableCode, _ := totp.GenerateCode(enrollment.Secret, time.Now().UTC())
	err = svc.DisableTOTP(ctx, newSess.Token, "valid_password_123", disableCode)
	if err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}

	// User should now have TOTP disabled
	dbUser, _ = uRepo.FindByUsername(ctx, "totpuser")
	if dbUser.TOTPEnabled || dbUser.TOTPSecret != nil {
		t.Fatalf("TOTP should be disabled")
	}
}
