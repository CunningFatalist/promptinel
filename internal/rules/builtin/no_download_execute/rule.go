package nodownloadexecute

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-download-execute"
	name        = "No Download Then Execute"
	summary     = "Detects mixed download and execution signals in one segment"
	description = "Combining remote download references with execution commands can indicate remote code execution intent."
)

// Rule detects download-and-execute patterns.
type Rule struct{}

// New returns the no-download-execute rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-download-execute rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-download-execute rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckTokens detects combined download and execution signals.
func (Rule) CheckTokens(ctx rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.CanExecuteShell() {
		return nil
	}

	hasURL := false
	executionToken := -1

	for i, token := range tokens {
		if token.Type == lexer.TokenURL {
			hasURL = true
		}

		if token.Type == lexer.TokenShellCommand {
			if _, ok := signals.ExecutionCommands[strings.ToLower(token.Value)]; ok {
				executionToken = i
			}
			continue
		}

		if token.Type != lexer.TokenWord {
			continue
		}
		if _, ok := signals.ExecutionCommands[strings.ToLower(token.Value)]; ok {
			executionToken = i
		}
	}

	if !hasURL || executionToken == -1 {
		return nil
	}

	return []rules.Finding{{
		Message:  "Remote download appears combined with execution",
		Position: tokens[executionToken].Position,
	}}
}
