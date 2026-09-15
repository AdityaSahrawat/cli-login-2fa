package cli

import (
	"strings"
	"testing"

	"github.com/chzyer/readline"
)

func TestGhostCompleter_UnauthSuggestions(t *testing.T) {
	gc := newGhostCompleter(func() bool { return false }, func() bool { return true })

	tests := []struct {
		input       string
		expectMatch string
		expectHint  string
	}{
		{"h", "help", "elp [Tab]"},
		{"l", "login", "ogin [Tab]"},
		{"r", "register", "egister [Tab]"},
		{"ex", "exit", "it [Tab]"},
		{"xyz", "", ""},
		{"help", "", ""}, // already complete
	}

	for _, tc := range tests {
		line := []rune(tc.input)
		painted := gc.Paint(line, len(line))
		paintedStr := string(painted)

		if tc.expectHint == "" {
			if paintedStr != tc.input {
				t.Errorf("input %q: expected no ghost text, got %q", tc.input, paintedStr)
			}
		} else {
			if !strings.Contains(paintedStr, tc.expectHint) {
				t.Errorf("input %q: expected painted output to contain %q, got %q", tc.input, tc.expectHint, paintedStr)
			}
			if !strings.Contains(paintedStr, "\033[90m") {
				t.Errorf("input %q: expected ANSI dark gray escape code in output", tc.input)
			}
		}
	}
}

func TestGhostCompleter_AuthSuggestions(t *testing.T) {
	gc := newGhostCompleter(func() bool { return true }, func() bool { return true })

	tests := []struct {
		input       string
		expectHint  string
	}{
		{"w", "hoami [Tab]"},
		{"en", "able-2fa [Tab]"},
		{"di", "sable-2fa [Tab]"},
		{"lo", "gout [Tab]"},
		{"h", "elp [Tab]"},
	}

	for _, tc := range tests {
		line := []rune(tc.input)
		painted := gc.Paint(line, len(line))
		paintedStr := string(painted)

		if !strings.Contains(paintedStr, tc.expectHint) {
			t.Errorf("auth input %q: expected hint %q, got %q", tc.input, tc.expectHint, paintedStr)
		}
	}
}

func TestGhostCompleter_CursorNotAtEnd(t *testing.T) {
	gc := newGhostCompleter(func() bool { return false }, func() bool { return true })

	line := []rune("he")
	// Pos is 1 instead of 2 (cursor in the middle)
	painted := gc.Paint(line, 1)
	if string(painted) != "he" {
		t.Errorf("expected no ghost text when cursor is not at the end of the line, got %q", string(painted))
	}
}

func TestGhostCompleter_SubPromptDisabled(t *testing.T) {
	// When at a subprompt (e.g. Username: or TOTP code:), isMainPrompt is false
	gc := newGhostCompleter(func() bool { return false }, func() bool { return false })

	line := []rune("h")
	painted := gc.Paint(line, len(line))
	if string(painted) != "h" {
		t.Errorf("expected no ghost text in sub-prompts, got %q", string(painted))
	}
}

func TestGhostCompleter_RightArrowAccept(t *testing.T) {
	gc := newGhostCompleter(func() bool { return false }, func() bool { return true })

	line := []rune("h")
	newLine, newPos, ok := gc.OnChange(line, 1, readline.CharForward)
	if !ok {
		t.Fatalf("expected Right-Arrow to accept suggestion")
	}
	if string(newLine) != "help" {
		t.Errorf("expected new line to be 'help', got %q", string(newLine))
	}
	if newPos != 4 {
		t.Errorf("expected new pos to be 4, got %d", newPos)
	}
}

func TestGhostCompleter_EnterDisablesGhostText(t *testing.T) {
	gc := newGhostCompleter(func() bool { return false }, func() bool { return true })

	line := []rune("h")
	// User hits enter
	_, _, _ = gc.OnChange(line, 1, readline.CharEnter)

	painted := gc.Paint(line, 1)
	if string(painted) != "h" {
		t.Errorf("expected ghost text to be suppressed during Enter submission, got %q", string(painted))
	}
}
