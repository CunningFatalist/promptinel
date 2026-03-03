package nocommandchaining

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-command-chaining"
	name        = "No Command Chaining"
	summary     = "Detects chained shell command operators"
	description = "Shell chaining operators like ';', '&&', and '||' often indicate complex or evasive execution flows."
)

// Rule detects shell command chaining patterns.
type Rule struct{}

// New returns the no-command-chaining rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-command-chaining rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-command-chaining rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckTokens detects chained shell command operators.
func (Rule) CheckTokens(ctx rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanExecuteShell() {
		return nil
	}

	for i := range tokens {
		token := tokens[i]
		if token.Value == ";" {
			if isChainedCommand(tokens, i, i+1) {
				return []rules.Finding{{
					Message:  "Shell command chaining operator detected",
					Position: token.Position,
				}}
			}
		}

		if i+1 >= len(tokens) {
			continue
		}
		if token.Value == "&" && tokens[i+1].Value == "&" {
			if isChainedCommand(tokens, i, i+2) {
				return []rules.Finding{{
					Message:  "Shell command chaining operator detected",
					Position: token.Position,
				}}
			}
		}
		if token.Value == "|" && tokens[i+1].Value == "|" {
			if isChainedCommand(tokens, i, i+2) {
				return []rules.Finding{{
					Message:  "Shell command chaining operator detected",
					Position: token.Position,
				}}
			}
		}
	}

	return nil
}

func isChainedCommand(tokens []rules.Token, operatorStart int, afterStart int) bool {
	hasShellBefore := false
	for i := operatorStart - 1; i >= 0; i-- {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		if token.Type == lexer.TokenShellCommand {
			hasShellBefore = true
			break
		}
	}
	if !hasShellBefore {
		return false
	}

	for i := afterStart; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		return token.Type == lexer.TokenShellCommand || token.Type == lexer.TokenWord || token.Type == lexer.TokenPath
	}

	return false
}
