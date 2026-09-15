package app

import (
	"context"
	"database/sql"
	"fmt"

	"cli-login/internal/auth"
	"cli-login/internal/cli"
	"cli-login/internal/config"
	"cli-login/internal/database"
)

// App is the root dependency container for the application.
type App struct {
	cfg         *config.Config
	db          *sql.DB
	userRepo    database.UserRepository
	sessionRepo database.SessionRepository
	authService auth.AuthService
	shell       *cli.Shell
}

// New initializes the application container with configuration.
func New(cfg *config.Config) *App {
	return &App{cfg: cfg}
}

// Start opens database, applies migrations, constructs services, and runs the CLI loop.
func (a *App) Start(ctx context.Context) error {
	db, err := database.Connect(ctx, a.cfg)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	a.db = db
	defer a.db.Close()

	if err := database.RunMigrations(ctx, a.db); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	a.userRepo = database.NewPostgresUserRepository(a.db)
	a.sessionRepo = database.NewPostgresSessionRepository(a.db)
	a.authService = auth.NewService(a.cfg, a.userRepo, a.sessionRepo)

	shell, err := cli.NewShell(a.cfg, a.authService)
	if err != nil {
		return fmt.Errorf("failed to start interactive shell: %w", err)
	}
	a.shell = shell

	return a.shell.Run(ctx)
}
