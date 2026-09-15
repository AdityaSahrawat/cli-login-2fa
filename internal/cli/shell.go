package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cli-login/internal/auth"
	"cli-login/internal/config"
	"cli-login/internal/models"

	"github.com/chzyer/readline"
)

// Shell manages the readline loop and dispatches commands based on authentication state.
type Shell struct {
	cfg         *config.Config
	authService auth.AuthService
	rl          *readline.Instance
	handler     *CommandHandler
	session     *models.AuthenticatedSession
}

// NewShell initializes the readline instance and shell dependencies.
func NewShell(cfg *config.Config, authService auth.AuthService) (*Shell, error) {
	// Ensure history directory exists
	histDir := filepath.Dir(cfg.ReadlineHistoryFile)
	if histDir != "" && histDir != "." {
		_ = os.MkdirAll(histDir, 0755)
	}

	completer := readline.NewPrefixCompleter(
		readline.PcItem("register"),
		readline.PcItem("login"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "cli-login> ",
		HistoryFile:     cfg.ReadlineHistoryFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize readline: %w", err)
	}

	prompter := NewPrompter(rl)
	handler := NewCommandHandler(authService, prompter, rl.Stdout())

	return &Shell{
		cfg:         cfg,
		authService: authService,
		rl:          rl,
		handler:     handler,
	}, nil
}

// Close closes the readline resources cleanly.
func (s *Shell) Close() error {
	return s.rl.Close()
}

func (s *Shell) updateCompleter() {
	if s.session != nil {
		s.rl.Config.AutoComplete = readline.NewPrefixCompleter(
			readline.PcItem("whoami"),
			readline.PcItem("enable-2fa"),
			readline.PcItem("disable-2fa"),
			readline.PcItem("logout"),
			readline.PcItem("help"),
			readline.PcItem("exit"),
		)
		s.rl.SetPrompt(fmt.Sprintf("cli-login(%s)> ", s.session.Username))
	} else {
		s.rl.Config.AutoComplete = readline.NewPrefixCompleter(
			readline.PcItem("register"),
			readline.PcItem("login"),
			readline.PcItem("help"),
			readline.PcItem("exit"),
		)
		s.rl.SetPrompt("cli-login> ")
	}
}

// Run executes the command loop until exit or EOF.
func (s *Shell) Run(ctx context.Context) error {
	defer s.Close()

	fmt.Fprintln(s.rl.Stdout(), "Welcome to CLI Login System. Type 'help' to see available commands.")

	for {
		line, err := s.rl.Readline()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				continue
			}
			if errors.Is(err, io.EOF) {
				s.handler.HandleExit(ctx, s.currentToken())
				return nil
			}
			return err
		}

		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}

		s.executeCommand(ctx, cmd)
	}
}

func (s *Shell) currentToken() string {
	if s.session != nil {
		return s.session.Token
	}
	return ""
}

func (s *Shell) clearSession() {
	s.session = nil
	s.updateCompleter()
}

func (s *Shell) executeCommand(ctx context.Context, cmd string) {
	authenticated := s.session != nil

	switch cmd {
	case "help":
		s.handler.HandleHelp(authenticated)

	case "exit":
		s.handler.HandleExit(ctx, s.currentToken())

	case "register":
		if authenticated {
			fmt.Fprintln(s.rl.Stdout(), "You are already logged in. Type 'logout' to log out first.")
			return
		}
		if err := s.handler.HandleRegister(ctx); err != nil {
			fmt.Fprintf(s.rl.Stdout(), "%s\n", err.Error())
		}

	case "login":
		if authenticated {
			fmt.Fprintln(s.rl.Stdout(), "You are already logged in. Type 'logout' to log out first.")
			return
		}
		sess, err := s.handler.HandleLogin(ctx)
		if err != nil {
			fmt.Fprintf(s.rl.Stdout(), "%s\n", err.Error())
			return
		}
		s.session = sess
		s.updateCompleter()

	case "whoami":
		if !authenticated {
			fmt.Fprintln(s.rl.Stdout(), "You must be logged in to use this command.")
			return
		}
		if err := s.handler.HandleWhoami(ctx, s.session.Token); err != nil {
			fmt.Fprintf(s.rl.Stdout(), "%s\n", err.Error())
			if errors.Is(err, auth.ErrSessionExpired) || errors.Is(err, auth.ErrSessionRevoked) || errors.Is(err, auth.ErrNotAuthenticated) {
				s.clearSession()
			}
		}

	case "enable-2fa":
		if !authenticated {
			fmt.Fprintln(s.rl.Stdout(), "You must be logged in to use this command.")
			return
		}
		if err := s.handler.HandleEnable2FA(ctx, s.session.Token); err != nil {
			fmt.Fprintf(s.rl.Stdout(), "%s\n", err.Error())
			if errors.Is(err, auth.ErrSessionExpired) || errors.Is(err, auth.ErrSessionRevoked) {
				s.clearSession()
			}
		}

	case "disable-2fa":
		if !authenticated {
			fmt.Fprintln(s.rl.Stdout(), "You must be logged in to use this command.")
			return
		}
		if err := s.handler.HandleDisable2FA(ctx, s.session.Token); err != nil {
			fmt.Fprintf(s.rl.Stdout(), "%s\n", err.Error())
			if errors.Is(err, auth.ErrSessionExpired) || errors.Is(err, auth.ErrSessionRevoked) {
				s.clearSession()
			}
		}

	case "logout":
		if !authenticated {
			fmt.Fprintln(s.rl.Stdout(), "You are not logged in.")
			return
		}
		if err := s.handler.HandleLogout(ctx, s.session.Token); err != nil {
			fmt.Fprintf(s.rl.Stdout(), "%s\n", err.Error())
		}
		s.clearSession()

	default:
		fmt.Fprintln(s.rl.Stdout(), "Unknown command. Type 'help' to see available commands.")
	}
}
