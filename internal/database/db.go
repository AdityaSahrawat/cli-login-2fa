package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"cli-login/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Connect establishes a connection pool to PostgreSQL using config,
// sets pool parameters, and verifies connectivity with a retry backoff loop.
func Connect(ctx context.Context, cfg *config.Config) (*sql.DB, error) {
	dsn := cfg.DatabaseDSN()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database handle: %w", err)
	}

	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	db.SetMaxIdleConns(cfg.DBMaxIdleConns)
	db.SetConnMaxLifetime(time.Hour)

	// Retry pinging database up to 30 times (1 second sleep) to handle container startup delay
	maxAttempts := 30
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err = db.PingContext(pingCtx)
		cancel()

		if err == nil {
			return db, nil
		}

		lastErr = err
		select {
		case <-ctx.Done():
			db.Close()
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	db.Close()
	return nil, fmt.Errorf("failed to connect to PostgreSQL at %s:%d after %d attempts: %w",
		cfg.DBHost, cfg.DBPort, maxAttempts, lastErr)
}
