package nointerpreterinlineexec

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-interpreter-inline-exec"
	name        = "No Interpreter Inline Exec"
	summary     = "Detects inline interpreter execution flags"
	description = "Inline interpreter execution flags like python -c or node -e can be used to execute injected payloads directly."
)

// Rule detects inline interpreter execution usage.
type Rule struct{}

// New returns the no-interpreter-inline-exec rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-interpreter-inline-exec rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-interpreter-inline-exec rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckTokens detects inline execution flags for common interpreters.
func (Rule) CheckTokens(ctx rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanExecuteShell() {
		return nil
	}

	for i := range tokens {
		token := tokens[i]
		if token.Type != lexer.TokenShellCommand && token.Type != lexer.TokenWord {
			continue
		}
		interpreter := strings.ToLower(token.Value)
		flags, ok := signals.InlineInterpreterFlags[interpreter]
		if !ok {
			continue
		}

		flag, payloadStart, hasFlag := readFlag(tokens, i+1)
		if !hasFlag {
			continue
		}
		if _, ok := flags[flag]; !ok {
			continue
		}

		if !hasInlinePayload(tokens, payloadStart) {
			continue
		}

		return []rules.Finding{{
			Message:  "Inline interpreter execution flag detected",
			Position: token.Position,
		}}
	}

	return nil
}

func readFlag(tokens []rules.Token, start int) (string, int, bool) {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		if token.Value == ";" || token.Value == "|" {
			return "", 0, false
		}
		if token.Value == "-" {
			next, nextIndex := nextSignificantToken(tokens, i+1)
			if next == nil {
				return "", 0, false
			}
			return strings.ToLower(next.Value), nextIndex + 1, true
		}
		if strings.HasPrefix(token.Value, "-") {
			return strings.ToLower(strings.TrimLeft(token.Value, "-")), i + 1, true
		}
		return "", 0, false
	}
	return "", 0, false
}

func hasInlinePayload(tokens []rules.Token, start int) bool {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		if token.Value == ";" || token.Value == "|" {
			return false
		}
		return true
	}
	return false
}

func nextSignificantToken(tokens []rules.Token, start int) (*rules.Token, int) {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		return &tokens[i], i
	}
	return nil, -1
}
