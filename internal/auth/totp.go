package auth

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cli-login/internal/config"
	"cli-login/internal/models"

	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

// GenerateTOTPKey creates a new TOTP key in memory for enrollment.
func GenerateTOTPKey(cfg *config.Config, username string) (*models.TOTPEnrollment, string, error) {
	period := cfg.TOTPPeriodSeconds
	if period <= 0 {
		period = 30
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.TOTPIssuer,
		AccountName: username,
		Period:      uint(period),
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	secret := key.Secret()
	otpauthURL := key.URL()

	// Ensure directory for QR code exists
	dir := filepath.Dir(cfg.ReadlineHistoryFile)
	if dir == "" || dir == "." {
		dir = "/app/data"
	}
	_ = os.MkdirAll(dir, 0755)

	qrPath := filepath.Join(dir, fmt.Sprintf("totp-%s.png", username))
	if err := qrcode.WriteFile(otpauthURL, qrcode.Medium, 256, qrPath); err != nil {
		qrPath = ""
	}

	enrollment := &models.TOTPEnrollment{
		Secret:  secret,
		QRPath:  qrPath,
		Issuer:  cfg.TOTPIssuer,
		Account: username,
	}

	return enrollment, otpauthURL, nil
}

// RenderTerminalQR renders an ANSI QR code to the provided writer.
func RenderTerminalQR(w io.Writer, otpauthURL string) {
	cfg := qrterminal.Config{
		Level:      qrterminal.M,
		Writer:     w,
		HalfBlocks: true,
	}
	qrterminal.GenerateWithConfig(otpauthURL, cfg)
}

// ValidateTOTP verifies a 6-digit TOTP code against a secret at the given time with skew.
func ValidateTOTP(cfg *config.Config, secret, code string, now time.Time) (bool, error) {
	period := cfg.TOTPPeriodSeconds
	if period <= 0 {
		period = 30
	}
	return totp.ValidateCustom(code, secret, now.UTC(), totp.ValidateOpts{
		Period:    uint(period),
		Skew:      uint(cfg.TOTPSkewPeriods),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}
