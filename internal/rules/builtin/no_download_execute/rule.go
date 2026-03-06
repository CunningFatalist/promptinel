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

var inlineExecInterpreters = map[string]struct{}{
	"bash":       {},
	"sh":         {},
	"zsh":        {},
	"pwsh":       {},
	"powershell": {},
	"cmd":        {},
	"cmd.exe":    {},
	"python":     {},
	"python3":    {},
	"node":       {},
	"ruby":       {},
	"php":        {},
	"perl":       {},
}

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
	hasDownload := false
	executionToken := -1

	for i, token := range tokens {
		if token.Type == lexer.TokenURL {
			hasURL = true
		}

		if token.Type == lexer.TokenShellCommand {
			lower := strings.ToLower(token.Value)
			if _, ok := signals.ExecutionCommands[lower]; ok {
				executionToken = i
			}
			if _, ok := signals.DownloadSignals[lower]; ok {
				hasDownload = true
			}
			if isInlineExecInterpreter(tokens, i, lower) {
				executionToken = i
			}
			continue
		}

		if token.Type != lexer.TokenWord && token.Type != lexer.TokenPath {
			continue
		}
		lower := strings.ToLower(token.Value)
		if _, ok := signals.ExecutionCommands[lower]; ok {
			executionToken = i
		}
		if _, ok := signals.DownloadSignals[lower]; ok {
			hasDownload = true
		}
		if lower == "downloadstring" || lower == "downloadfile" {
			hasDownload = true
		}
	}

	if !hasDownload || !hasURL || executionToken == -1 {
		return nil
	}

	return []rules.Finding{{
		Message:  "Remote download appears combined with execution",
		Position: tokens[executionToken].Position,
	}}
}

func isInlineExecInterpreter(tokens []rules.Token, index int, lower string) bool {
	if _, ok := inlineExecInterpreters[lower]; !ok {
		return false
	}
	for i := index + 1; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		if token.Value == ";" || token.Value == "|" || token.Value == "&" {
			return false
		}
		if token.Value == "/" {
			next := nextSignificantToken(tokens, i+1)
			if next == nil {
				return false
			}
			return strings.EqualFold(next.Value, "c")
		}
		if token.Value == "-" {
			next := nextSignificantToken(tokens, i+1)
			if next == nil {
				return false
			}
			flag := strings.ToLower(next.Value)
			return flag == "c" || flag == "e" || flag == "r" || flag == "command" || flag == "encodedcommand"
		}
		if strings.HasPrefix(token.Value, "-") || strings.HasPrefix(token.Value, "/") {
			flag := strings.TrimLeft(strings.ToLower(token.Value), "-/")
			return flag == "c" || flag == "e" || flag == "r" || flag == "command" || flag == "encodedcommand"
		}
		return false
	}
	return false
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
