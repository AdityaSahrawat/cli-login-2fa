package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"cli-login/internal/auth"
	"cli-login/internal/models"
)

// CommandHandler executes CLI commands.
type CommandHandler struct {
	authService auth.AuthService
	prompter    *Prompter
	out         io.Writer
}

// NewCommandHandler creates a new CommandHandler.
func NewCommandHandler(authService auth.AuthService, prompter *Prompter, out io.Writer) *CommandHandler {
	return &CommandHandler{
		authService: authService,
		prompter:    prompter,
		out:         out,
	}
}

func (h *CommandHandler) HandleRegister(ctx context.Context) error {
	username, err := h.prompter.PromptLine("Username: ")
	if err != nil {
		return err
	}

	password, err := h.prompter.PromptPassword("Password: ")
	if err != nil {
		return err
	}

	confirm, err := h.prompter.PromptPassword("Confirm password: ")
	if err != nil {
		return err
	}

	if err := h.authService.Register(ctx, username, password, confirm); err != nil {
		return err
	}

	fmt.Fprintln(h.out, "Registration successful.")
	return nil
}

func (h *CommandHandler) HandleLogin(ctx context.Context) (*models.AuthenticatedSession, error) {
	username, err := h.prompter.PromptLine("Username: ")
	if err != nil {
		return nil, err
	}

	password, err := h.prompter.PromptPassword("Password: ")
	if err != nil {
		return nil, err
	}

	sess, err := h.authService.Login(ctx, username, password, "")
	if err != nil {
		if errors.Is(err, auth.ErrTOTPRequired) {
			totpCode, err := h.prompter.PromptLine("TOTP code: ")
			if err != nil {
				return nil, err
			}
			sess, err = h.authService.Login(ctx, username, password, totpCode)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// Fetch user details to display formatted summary
	user, session, err := h.authService.GetCurrentUser(ctx, sess.Token)
	if err == nil && user != nil {
		mfaStatus := "disabled"
		if user.TOTPEnabled {
			mfaStatus = "enabled"
		}

		lastLoginStr := "First login"
		if user.LastLoginAt != nil {
			lastLoginStr = user.LastLoginAt.Format(time.RFC3339)
		}

		fmt.Fprintln(h.out, "\nLogin successful.")
		fmt.Fprintf(h.out, "Username: %s\n", user.Username)
		fmt.Fprintf(h.out, "Registration date: %s\n", user.RegisteredAt.Format(time.RFC3339))
		fmt.Fprintf(h.out, "MFA status: %s\n", mfaStatus)
		fmt.Fprintf(h.out, "Session expires: %s\n", session.ExpiresAt.Format(time.RFC3339))
		fmt.Fprintf(h.out, "Last login: %s\n", lastLoginStr)
	} else {
		fmt.Fprintln(h.out, "Login successful.")
	}

	return sess, nil
}

func (h *CommandHandler) HandleWhoami(ctx context.Context, rawToken string) error {
	user, session, err := h.authService.GetCurrentUser(ctx, rawToken)
	if err != nil {
		return err
	}

	mfaStatus := "disabled"
	if user.TOTPEnabled {
		mfaStatus = "enabled"
	}

	lastLoginStr := "First login"
	if user.LastLoginAt != nil {
		lastLoginStr = user.LastLoginAt.Format(time.RFC3339)
	}

	fmt.Fprintf(h.out, "Username: %s\n", user.Username)
	fmt.Fprintf(h.out, "Registration date: %s\n", user.RegisteredAt.Format(time.RFC3339))
	fmt.Fprintf(h.out, "MFA status: %s\n", mfaStatus)
	fmt.Fprintf(h.out, "Session expires: %s\n", session.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(h.out, "Last login: %s\n", lastLoginStr)
	return nil
}

func (h *CommandHandler) HandleEnable2FA(ctx context.Context, rawToken string) error {
	enrollment, err := h.authService.BeginTOTPEnrollment(ctx, rawToken)
	if err != nil {
		return err
	}

	fmt.Fprintln(h.out, "A QR code has been generated. Scan it with Google Authenticator:")
	// Render terminal ANSI QR code
	otpauthURL := fmt.Sprintf("otpauth://totp/%s:%s?issuer=%s&secret=%s",
		enrollment.Issuer, enrollment.Account, enrollment.Issuer, enrollment.Secret)
	auth.RenderTerminalQR(h.out, otpauthURL)

	if enrollment.QRPath != "" {
		fmt.Fprintf(h.out, "QR code image saved to: %s\n", enrollment.QRPath)
	}

	code, err := h.prompter.PromptLine("Enter the 6-digit code to confirm: ")
	if err != nil {
		return err
	}

	if err := h.authService.ConfirmTOTPEnrollment(ctx, rawToken, code, enrollment); err != nil {
		return err
	}

	fmt.Fprintln(h.out, "2FA enabled successfully.")
	return nil
}

func (h *CommandHandler) HandleDisable2FA(ctx context.Context, rawToken string) error {
	user, _, err := h.authService.GetCurrentUser(ctx, rawToken)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled {
		return auth.ErrTOTPNotEnabled
	}

	password, err := h.prompter.PromptPassword("Enter current password: ")
	if err != nil {
		return err
	}

	code, err := h.prompter.PromptLine("Enter current TOTP code: ")
	if err != nil {
		return err
	}

	if err := h.authService.DisableTOTP(ctx, rawToken, password, code); err != nil {
		return err
	}

	fmt.Fprintln(h.out, "2FA disabled successfully.")
	return nil
}

func (h *CommandHandler) HandleLogout(ctx context.Context, rawToken string) error {
	err := h.authService.Logout(ctx, rawToken)
	if err != nil {
		return err
	}
	fmt.Fprintln(h.out, "Logged out successfully.")
	return nil
}

func (h *CommandHandler) HandleHelp(authenticated bool) {
	fmt.Fprintln(h.out, "Available commands:")
	if authenticated {
		fmt.Fprintln(h.out, "  whoami         Display current user information")
		fmt.Fprintln(h.out, "  enable-2fa     Enroll in two-factor authentication")
		fmt.Fprintln(h.out, "  disable-2fa    Disable two-factor authentication")
		fmt.Fprintln(h.out, "  logout         Log out of current session")
		fmt.Fprintln(h.out, "  help           Show this help")
		fmt.Fprintln(h.out, "  exit           Exit the application")
	} else {
		fmt.Fprintln(h.out, "  register       Create a new user")
		fmt.Fprintln(h.out, "  login          Log in")
		fmt.Fprintln(h.out, "  help           Show this help")
		fmt.Fprintln(h.out, "  exit           Exit the application")
	}
}

func (h *CommandHandler) HandleExit(ctx context.Context, rawToken string) {
	if rawToken != "" {
		_ = h.authService.Logout(ctx, rawToken)
	}
	fmt.Fprintln(h.out, "Goodbye.")
	os.Exit(0)
}
