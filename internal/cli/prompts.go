package cli

import (
	"fmt"
	"strings"

	"github.com/chzyer/readline"
)

// Prompter provides helper methods to interactively read user input.
type Prompter struct {
	rl *readline.Instance
}

// NewPrompter creates a new Prompter wrapping an active readline instance.
func NewPrompter(rl *readline.Instance) *Prompter {
	return &Prompter{rl: rl}
}

// PromptLine displays a prompt and reads a trimmed line of text.
func (p *Prompter) PromptLine(promptText string) (string, error) {
	oldPrompt := p.rl.Config.Prompt
	p.rl.SetPrompt(promptText)
	defer p.rl.SetPrompt(oldPrompt)

	line, err := p.rl.Readline()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// PromptPassword displays a prompt and reads a password without echoing characters.
func (p *Prompter) PromptPassword(promptText string) (string, error) {
	bytes, err := p.rl.ReadPassword(promptText)
	if err != nil {
		return "", err
	}
	// Print a newline after hidden password input
	fmt.Println()
	return string(bytes), nil
}
