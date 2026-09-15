package tests

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"cli-login/internal/config"
	"cli-login/internal/database"
	"cli-login/internal/models"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func getTestDB(t *testing.T) *sql.DB {
	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := 5430
	if pStr := os.Getenv("DB_PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil {
			port = p
		}
	}
	user := os.Getenv("DB_USER")
	if user == "" {
		user = "cli_user"
	}
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		password = "cli_secret"
	}
	dbname := os.Getenv("DB_NAME")
	if dbname == "" {
		dbname = "cli_login_db"
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, password, host, port, dbname)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Skipf("skipping PostgreSQL integration test: open failed: %v", err)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("skipping PostgreSQL integration test: database not reachable at %s:%d (run 'docker compose up -d postgres' to run live DB tests)", host, port)
		return nil
	}

	return db
}

func TestPostgresIntegration(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()

	// Apply migrations
	err := database.RunMigrations(ctx, db)
	if err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	userRepo := database.NewPostgresUserRepository(db)
	sessRepo := database.NewPostgresSessionRepository(db)

	testUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
	u := &models.User{
		Username:       testUsername,
		PasswordHash:   "$2a$12$dummyhashfordbtestingonly12345678901234567890",
		RegisteredAt:   time.Now().UTC(),
		FailedAttempts: 0,
		TOTPEnabled:    false,
	}

	// 1. Create user
	if err := userRepo.Create(ctx, u); err != nil {
		t.Fatalf("failed to create user in DB: %v", err)
	}

	// 2. Duplicate user
	if err := userRepo.Create(ctx, u); err != database.ErrDuplicateUsername {
		t.Errorf("expected ErrDuplicateUsername, got %v", err)
	}

	// 3. Find by username (case-insensitive via citext)
	found, err := userRepo.FindByUsername(ctx, testUsername)
	if err != nil {
		t.Fatalf("failed to find user by username: %v", err)
	}
	if found.ID != u.ID {
		t.Errorf("expected ID %d, got %d", u.ID, found.ID)
	}

	// 4. Record failed attempts and lockout
	now := time.Now().UTC()
	err = userRepo.RecordFailedLogin(ctx, u.ID, now, 5, 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to record failed login: %v", err)
	}

	// 5. Create and revoke session
	sess := &models.Session{
		UserID:    u.ID,
		TokenHash: fmt.Sprintf("dummytokenhash_%d", time.Now().UnixNano()),
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}
	if err := sessRepo.Create(ctx, sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	if err := sessRepo.Revoke(ctx, sess.TokenHash, now); err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}

	s, err := sessRepo.FindByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("failed to find session: %v", err)
	}
	if s.RevokedAt == nil {
		t.Errorf("expected session to be revoked")
	}
}

func init() {
	if os.Getenv("ENCRYPTION_KEY") == "" {
		_ = os.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	}
	_ = config.Config{}
}
