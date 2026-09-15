package cli

import (
	"strings"

	"github.com/chzyer/readline"
)

var (
	unauthCommands = []string{"help", "login", "register", "exit"}
	authCommands   = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}
)

// ghostCompleter implements readline.Painter and readline.Listener to provide
// inline ghost-text autosuggestions and Tab/Right-Arrow hints.
type ghostCompleter struct {
	isAuthenticated func() bool
	isMainPrompt    func() bool
	isSubmitting    bool
}

func newGhostCompleter(isAuthenticated func() bool, isMainPrompt func() bool) *ghostCompleter {
	return &ghostCompleter{
		isAuthenticated: isAuthenticated,
		isMainPrompt:    isMainPrompt,
	}
}

func (g *ghostCompleter) getCommands() []string {
	if g.isAuthenticated != nil && g.isAuthenticated() {
		return authCommands
	}
	return unauthCommands
}

func (g *ghostCompleter) getMatch(input string) string {
	if input == "" {
		return ""
	}
	for _, cmd := range g.getCommands() {
		if strings.HasPrefix(cmd, input) && cmd != input {
			return cmd
		}
	}
	return ""
}

// Paint paints the line runes. When the cursor is at the end of an incomplete command,
// it appends faint ghost text and a "[Tab]" indicator in dark gray (\033[90m),
// then uses backspaces to keep the cursor positioned right where the user is typing.
func (g *ghostCompleter) Paint(line []rune, pos int) []rune {
	if g.isSubmitting || len(line) == 0 || pos != len(line) {
		return line
	}

	if g.isMainPrompt != nil && !g.isMainPrompt() {
		return line
	}

	str := string(line)
	if strings.Contains(str, " ") {
		return line
	}

	match := g.getMatch(str)
	if match == "" {
		return line
	}

	suffix := match[len(str):]
	hint := suffix + " [Tab]"

	// Append: ANSI dim/light gray (\033[90m) + hint + ANSI reset (\033[0m) + backspaces
	result := make([]rune, 0, len(line)+len(hint)+20)
	result = append(result, line...)
	result = append(result, []rune("\033[90m")...)
	result = append(result, []rune(hint)...)
	result = append(result, []rune("\033[0m")...)
	for i := 0; i < len(hint); i++ {
		result = append(result, '\b')
	}

	return result
}

// OnChange handles keypresses:
// - Enter: sets isSubmitting to true to ensure no trailing ghost text is left on submitted lines.
// - Right Arrow (CharForward): accepts the current ghost suggestion when pressed at the end of the line.
func (g *ghostCompleter) OnChange(line []rune, pos int, key rune) (newLine []rune, newPos int, ok bool) {
	if key == readline.CharEnter || key == readline.CharCtrlJ {
		g.isSubmitting = true
		return nil, 0, false
	}
	g.isSubmitting = false

	if key == readline.CharForward && pos == len(line) {
		if g.isMainPrompt != nil && !g.isMainPrompt() {
			return nil, 0, false
		}
		str := string(line)
		if !strings.Contains(str, " ") {
			match := g.getMatch(str)
			if match != "" {
				return []rune(match), len(match), true
			}
		}
	}

	return nil, 0, false
}
