package auth

import (
	"context"
	"errors"
	"os"
	"time"

	"cli-login/internal/config"
	"cli-login/internal/database"
	"cli-login/internal/models"
	"cli-login/internal/security"
)

var (
	ErrInvalidCredentials = errors.New("Login failed: invalid credentials.")
	ErrAccountLocked      = errors.New("Account temporarily locked. Try again later.")
	ErrSessionExpired     = errors.New("Session expired. Please log in again.")
	ErrSessionRevoked     = errors.New("Session expired. Please log in again.")
	ErrNotAuthenticated   = errors.New("You must be logged in to use this command.")
	ErrTOTPAlreadyEnabled = errors.New("2FA is already enabled for this account.")
	ErrTOTPNotEnabled     = errors.New("2FA is not enabled for this account.")
	ErrTOTPRequired       = errors.New("TOTP_REQUIRED")
	ErrInvalidTOTP        = errors.New("Authentication failed: invalid verification code.")
)

// AuthService coordinates registration, login, logout, and authenticated operations.
type AuthService interface {
	Register(ctx context.Context, username, password, confirm string) error
	Login(ctx context.Context, username, password, totpCode string) (*models.AuthenticatedSession, error)
	Logout(ctx context.Context, rawToken string) error
	GetCurrentUser(ctx context.Context, rawToken string) (*models.User, *models.Session, error)
	BeginTOTPEnrollment(ctx context.Context, rawToken string) (*models.TOTPEnrollment, error)
	ConfirmTOTPEnrollment(ctx context.Context, rawToken, code string, enrollment *models.TOTPEnrollment) error
	DisableTOTP(ctx context.Context, rawToken, password, code string) error
}

// Service is the concrete implementation of AuthService.
type Service struct {
	cfg         *config.Config
	userRepo    database.UserRepository
	sessionRepo database.SessionRepository
}

// NewService constructs a new AuthService.
func NewService(cfg *config.Config, userRepo database.UserRepository, sessionRepo database.SessionRepository) *Service {
	return &Service{
		cfg:         cfg,
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
	}
}

func (s *Service) Register(ctx context.Context, username, password, confirm string) error {
	trimmedUser := security.NormalizeUsername(username)
	if err := security.ValidateUsername(trimmedUser); err != nil {
		return err
	}

	if err := security.ValidatePasswordConfirmation(password, confirm); err != nil {
		return err
	}

	hash, err := HashPassword(password, s.cfg.BcryptCost)
	if err != nil {
		return err
	}

	u := &models.User{
		Username:       trimmedUser,
		PasswordHash:   hash,
		RegisteredAt:   time.Now().UTC(),
		FailedAttempts: 0,
		TOTPEnabled:    false,
	}

	return s.userRepo.Create(ctx, u)
}

func (s *Service) Login(ctx context.Context, username, password, totpCode string) (*models.AuthenticatedSession, error) {
	now := time.Now().UTC()
	trimmedUser := security.NormalizeUsername(username)

	user, err := s.userRepo.FindByUsername(ctx, trimmedUser)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			DummyCompare(s.cfg.BcryptCost)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Lockout verification before password check
	if IsLocked(user, now) {
		return nil, ErrAccountLocked
	}
	if IsLockExpired(user, now) {
		_ = s.userRepo.ResetLoginFailures(ctx, user.ID, now)
		user.FailedAttempts = 0
		user.LockedUntil = nil
	}

	// Verify password
	if err := ComparePassword(user.PasswordHash, password); err != nil {
		_ = s.userRepo.RecordFailedLogin(ctx, user.ID, now, s.cfg.MaxFailedAttempts, s.cfg.LockoutDuration())
		return nil, ErrInvalidCredentials
	}

	// If TOTP is enabled, verify code
	if user.TOTPEnabled {
		if totpCode == "" {
			return nil, ErrTOTPRequired
		}

		if user.TOTPSecret == nil {
			return nil, ErrInvalidTOTP
		}

		plainSecret, err := security.Decrypt(*user.TOTPSecret, s.cfg.EncryptionKey)
		if err != nil {
			return nil, ErrInvalidTOTP
		}

		valid, err := ValidateTOTP(s.cfg, plainSecret, totpCode, now)
		if err != nil || !valid {
			_ = s.userRepo.RecordFailedLogin(ctx, user.ID, now, s.cfg.MaxFailedAttempts, s.cfg.LockoutDuration())
			return nil, ErrInvalidTOTP
		}
	}

	// Reset failed attempts on full success and update last_login_at
	if err := s.userRepo.ResetLoginFailures(ctx, user.ID, now); err != nil {
		return nil, err
	}

	// Generate and persist session
	token, err := security.GenerateSessionToken()
	if err != nil {
		return nil, err
	}

	tokenHash := security.HashToken(token)
	expiresAt := now.Add(s.cfg.SessionTimeoutDuration())

	sess := &models.Session{
		UserID:    user.ID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	if err := s.sessionRepo.Create(ctx, sess); err != nil {
		return nil, err
	}

	return &models.AuthenticatedSession{
		UserID:    user.ID,
		Username:  user.Username,
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	tokenHash := security.HashToken(rawToken)
	return s.sessionRepo.Revoke(ctx, tokenHash, time.Now().UTC())
}

func (s *Service) GetCurrentUser(ctx context.Context, rawToken string) (*models.User, *models.Session, error) {
	if rawToken == "" {
		return nil, nil, ErrNotAuthenticated
	}

	now := time.Now().UTC()
	tokenHash := security.HashToken(rawToken)

	sess, err := s.sessionRepo.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, database.ErrSessionNotFound) {
			return nil, nil, ErrNotAuthenticated
		}
		return nil, nil, err
	}

	if IsSessionRevoked(sess) {
		return nil, nil, ErrSessionRevoked
	}
	if IsSessionExpired(sess, now) {
		return nil, nil, ErrSessionExpired
	}

	user, err := s.userRepo.FindByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}

	// Protect secrets from being exposed in user model
	sanitizedUser := *user
	sanitizedUser.PasswordHash = ""
	sanitizedUser.TOTPSecret = nil

	return &sanitizedUser, sess, nil
}

func (s *Service) BeginTOTPEnrollment(ctx context.Context, rawToken string) (*models.TOTPEnrollment, error) {
	user, _, err := s.GetCurrentUser(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	if user.TOTPEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}

	enrollment, _, err := GenerateTOTPKey(s.cfg, user.Username)
	if err != nil {
		return nil, err
	}

	return enrollment, nil
}

func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, rawToken, code string, enrollment *models.TOTPEnrollment) error {
	user, _, err := s.GetCurrentUser(ctx, rawToken)
	if err != nil {
		return err
	}

	if enrollment == nil || enrollment.Secret == "" {
		return errors.New("no pending TOTP enrollment found")
	}

	now := time.Now().UTC()
	valid, err := ValidateTOTP(s.cfg, enrollment.Secret, code, now)
	if err != nil || !valid {
		return ErrInvalidTOTP
	}

	encryptedSecret, err := security.Encrypt(enrollment.Secret, s.cfg.EncryptionKey)
	if err != nil {
		return err
	}

	if err := s.userRepo.UpdateTOTP(ctx, user.ID, true, &encryptedSecret); err != nil {
		return err
	}

	// Clean up temporary PNG file if present
	if enrollment.QRPath != "" {
		_ = os.Remove(enrollment.QRPath)
	}

	return nil
}

func (s *Service) DisableTOTP(ctx context.Context, rawToken, password, code string) error {
	user, _, err := s.GetCurrentUser(ctx, rawToken)
	if err != nil {
		return err
	}

	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	// Retrieve full user record with credentials for verification
	fullUser, err := s.userRepo.FindByID(ctx, user.ID)
	if err != nil {
		return err
	}

	if err := ComparePassword(fullUser.PasswordHash, password); err != nil {
		return ErrInvalidCredentials
	}

	if fullUser.TOTPSecret == nil {
		return ErrInvalidTOTP
	}

	plainSecret, err := security.Decrypt(*fullUser.TOTPSecret, s.cfg.EncryptionKey)
	if err != nil {
		return ErrInvalidTOTP
	}

	now := time.Now().UTC()
	valid, err := ValidateTOTP(s.cfg, plainSecret, code, now)
	if err != nil || !valid {
		return ErrInvalidTOTP
	}

	return s.userRepo.UpdateTOTP(ctx, user.ID, false, nil)
}
