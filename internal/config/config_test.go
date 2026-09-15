package config

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestConfigLoad(t *testing.T) {
	// Set valid 32-byte hex key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	hexKey := hex.EncodeToString(validKey)

	os.Setenv("ENCRYPTION_KEY", hexKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load successfully, got: %v", err)
	}

	if cfg.AppName != "cli-login" {
		t.Errorf("expected AppName cli-login, got %s", cfg.AppName)
	}
	if cfg.DBPort != 5432 {
		t.Errorf("expected DBPort 5432, got %d", cfg.DBPort)
	}
	if len(cfg.EncryptionKey) != 32 {
		t.Errorf("expected 32-byte encryption key, got %d", len(cfg.EncryptionKey))
	}
}

func TestConfigMissingKeyFails(t *testing.T) {
	os.Unsetenv("ENCRYPTION_KEY")

	_, err := Load()
	if err == nil {
		t.Errorf("expected error when ENCRYPTION_KEY is missing, got nil")
	}
}

func TestConfigInvalidPortFails(t *testing.T) {
	validKey := make([]byte, 32)
	os.Setenv("ENCRYPTION_KEY", hex.EncodeToString(validKey))
	os.Setenv("DB_PORT", "999999") // out of range
	defer os.Unsetenv("ENCRYPTION_KEY")
	defer os.Unsetenv("DB_PORT")

	_, err := Load()
	if err == nil {
		t.Errorf("expected error for out of range port, got nil")
	}
}
