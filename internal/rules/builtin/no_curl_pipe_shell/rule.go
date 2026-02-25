package nocurlpipeshell

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-curl-pipe-shell"
	name        = "No Curl/Wget Pipe To Shell"
	summary     = "Detects direct piping from network download commands into shell interpreters"
	description = "Piping curl/wget output directly to shell interpreters is a high-risk remote code execution pattern."
)

// Rule detects curl/wget pipeline execution patterns.
type Rule struct{}

// New returns the no-curl-pipe-shell rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-curl-pipe-shell rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-curl-pipe-shell rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckTokens detects curl/wget piped directly to shell interpreters.
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type != lexer.TokenShellCommand {
			continue
		}
		if _, ok := signals.DownloadCommands[strings.ToLower(token.Value)]; !ok {
			continue
		}

		pipeIndex := findPipeAhead(tokens, i+1)
		if pipeIndex == -1 {
			continue
		}

		next := nextSignificantToken(tokens, pipeIndex+1)
		if next == nil {
			continue
		}
		if _, ok := signals.ShellInterpreters[strings.ToLower(next.Value)]; !ok {
			continue
		}

		return []rules.Finding{{
			Message:  "Network download command piped to shell interpreter",
			Position: token.Position,
		}}
	}

	return nil
}

func findPipeAhead(tokens []rules.Token, start int) int {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace {
			continue
		}
		if token.Type == lexer.TokenNewline {
			return -1
		}
		if token.Value == ";" {
			return -1
		}
		if token.Value == "&" && i+1 < len(tokens) && tokens[i+1].Value == "&" {
			return -1
		}
		if token.Value == "|" && i+1 < len(tokens) && tokens[i+1].Value == "|" {
			return -1
		}
		if token.Value == "|" {
			return i
		}
	}
	return -1
}

func nextSignificantToken(tokens []rules.Token, start int) *rules.Token {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		return &tokens[i]
	}
	return nil
}
