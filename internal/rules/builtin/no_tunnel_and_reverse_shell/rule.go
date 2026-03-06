package notunnelandreverseshell

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-tunnel-and-reverse-shell"
	name        = "No Tunnel And Reverse Shell"
	summary     = "Detects reverse shell and tunneling instructions"
	description = "Reverse shell and tunnel setup commands can establish unauthorized remote control channels and should be blocked."
)

// Rule detects reverse shell and tunnel command patterns.
type Rule struct{}

// New returns the no-tunnel-and-reverse-shell rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-tunnel-and-reverse-shell rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-tunnel-and-reverse-shell rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects reverse shell/tunnel signals in token sequences and raw content.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanExecuteShell() || !ctx.CanAccessNetwork() {
		return nil
	}

	contentLower := strings.ToLower(doc.Document.Content)
	for _, snippet := range signals.ReverseShellSnippets {
		if index := strings.Index(contentLower, snippet); index >= 0 {
			return []rules.Finding{{
				Message:  "Reverse shell or tunneling pattern detected",
				Position: rules.PositionFromByteOffset(doc.Document.Content, index),
			}}
		}
	}

	for _, tokens := range doc.TokensBySegment {
		for i := range tokens {
			token := tokens[i]
			if token.Type != lexer.TokenShellCommand && token.Type != lexer.TokenWord {
				continue
			}

			lower := strings.ToLower(token.Value)
			switch lower {
			case "ngrok", "cloudflared", "chisel":
				return findingAt(token)
			case "ssh":
				if hasFlag(tokens, i+1, "r") {
					return findingAt(token)
				}
			case "nc", "ncat", "netcat":
				if hasFlag(tokens, i+1, "e") {
					return findingAt(token)
				}
			}
		}
	}

	return nil
}

func findingAt(token rules.Token) []rules.Finding {
	return []rules.Finding{{
		Message:  "Reverse shell or tunneling pattern detected",
		Position: token.Position,
	}}
}

func hasFlag(tokens []rules.Token, start int, expected string) bool {
	expectedShort := "-" + strings.ToLower(expected)
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		if token.Value == ";" || token.Value == "|" {
			return false
		}
		lower := strings.ToLower(token.Value)
		if lower == expectedShort {
			return true
		}
		if lower == "-" && i+1 < len(tokens) {
			next := strings.ToLower(tokens[i+1].Value)
			return next == strings.ToLower(expected)
		}
		return false
	}
	return false
}
