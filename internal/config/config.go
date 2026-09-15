package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration values for the application.
type Config struct {
	AppName               string
	DBHost                string
	DBPort                int
	DBUser                string
	DBPassword            string
	DBName                string
	DBSSLMode             string
	DBMaxOpenConns        int
	DBMaxIdleConns        int
	SessionTimeoutMinutes int
	MaxFailedAttempts     int
	LockoutMinutes        int
	BcryptCost            int
	TOTPPeriodSeconds     int
	TOTPSkewPeriods       int
	TOTPIssuer            string
	ReadlineHistoryFile   string
	EncryptionKey         []byte // 32 bytes for AES-256-GCM
}

// SessionTimeoutDuration returns the session timeout as a time.Duration.
func (c *Config) SessionTimeoutDuration() time.Duration {
	return time.Duration(c.SessionTimeoutMinutes) * time.Minute
}

// LockoutDuration returns the lockout period as a time.Duration.
func (c *Config) LockoutDuration() time.Duration {
	return time.Duration(c.LockoutMinutes) * time.Minute
}

// DatabaseDSN formats the PostgreSQL connection string.
func (c *Config) DatabaseDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName, c.DBSSLMode)
}

// Load reads configuration from environment variables, applies defaults, and validates values.
func Load() (*Config, error) {
	cfg := &Config{
		AppName:               getEnvString("APP_NAME", "cli-login"),
		DBHost:                getEnvString("DB_HOST", "postgres"),
		DBUser:                getEnvString("DB_USER", "cli_user"),
		DBPassword:            getEnvString("DB_PASSWORD", "cli_secret"),
		DBName:                getEnvString("DB_NAME", "cli_login_db"),
		DBSSLMode:             getEnvString("DB_SSLMODE", "disable"),
		TOTPIssuer:            getEnvString("TOTP_ISSUER", "CLI Login"),
		ReadlineHistoryFile:   getEnvString("READLINE_HISTORY_FILE", "/app/data/.cli_history"),
	}

	var err error
	if cfg.DBPort, err = getEnvInt("DB_PORT", 5432, 1, 65535); err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}
	if cfg.DBMaxOpenConns, err = getEnvInt("DB_MAX_OPEN_CONNS", 10, 1, 1000); err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_OPEN_CONNS: %w", err)
	}
	if cfg.DBMaxIdleConns, err = getEnvInt("DB_MAX_IDLE_CONNS", 5, 1, 1000); err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_IDLE_CONNS: %w", err)
	}
	if cfg.SessionTimeoutMinutes, err = getEnvInt("SESSION_TIMEOUT_MINUTES", 30, 1, 10080); err != nil {
		return nil, fmt.Errorf("invalid SESSION_TIMEOUT_MINUTES: %w", err)
	}
	if cfg.MaxFailedAttempts, err = getEnvInt("MAX_FAILED_ATTEMPTS", 5, 1, 100); err != nil {
		return nil, fmt.Errorf("invalid MAX_FAILED_ATTEMPTS: %w", err)
	}
	if cfg.LockoutMinutes, err = getEnvInt("LOCKOUT_MINUTES", 15, 1, 10080); err != nil {
		return nil, fmt.Errorf("invalid LOCKOUT_MINUTES: %w", err)
	}
	if cfg.BcryptCost, err = getEnvInt("BCRYPT_COST", 12, 4, 31); err != nil {
		return nil, fmt.Errorf("invalid BCRYPT_COST: %w", err)
	}
	if cfg.TOTPPeriodSeconds, err = getEnvInt("TOTP_PERIOD_SECONDS", 30, 10, 300); err != nil {
		return nil, fmt.Errorf("invalid TOTP_PERIOD_SECONDS: %w", err)
	}
	if cfg.TOTPSkewPeriods, err = getEnvInt("TOTP_SKEW_PERIODS", 1, 0, 5); err != nil {
		return nil, fmt.Errorf("invalid TOTP_SKEW_PERIODS: %w", err)
	}

	// Parse and validate ENCRYPTION_KEY (strictly 32 bytes for AES-256)
	rawKey := strings.TrimSpace(os.Getenv("ENCRYPTION_KEY"))
	if rawKey == "" {
		return nil, fmt.Errorf("configuration error: ENCRYPTION_KEY environment variable is required and cannot be empty")
	}

	// Support 64-char hex encoded keys or raw 32-byte string keys
	if len(rawKey) == 64 {
		decoded, err := hex.DecodeString(rawKey)
		if err != nil {
			return nil, fmt.Errorf("configuration error: ENCRYPTION_KEY hex decoding failed: %w", err)
		}
		cfg.EncryptionKey = decoded
	} else if len(rawKey) == 32 {
		cfg.EncryptionKey = []byte(rawKey)
	} else {
		return nil, fmt.Errorf("configuration error: ENCRYPTION_KEY must be exactly 32 bytes (or 64 hex characters), got length %d", len(rawKey))
	}

	return cfg, nil
}

func getEnvString(key, fallback string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	return val
}

func getEnvInt(key string, fallback, min, max int) (int, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback, nil
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", key, val)
	}
	if i < min || i > max {
		return 0, fmt.Errorf("%s value %d out of valid range [%d, %d]", key, i, min, max)
	}
	return i, nil
}
