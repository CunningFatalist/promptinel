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
func (Rule) CheckTokens(ctx rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.CanExecuteShell() {
		return nil
	}

	hasDownload := false
	for i := range tokens {
		token := tokens[i]
		lower := strings.ToLower(token.Value)
		if isDownloadSignal(token, lower) {
			hasDownload = true
		}

		if !isDownloadSignal(token, lower) {
			continue
		}

		if hasPipeToInterpreter(tokens, i+1) || hasPipeToPowerShellExec(tokens, i+1) {
			return []rules.Finding{{
				Message:  "Network download command piped to shell interpreter",
				Position: token.Position,
			}}
		}
	}

	for i := range tokens {
		token := tokens[i]
		lower := strings.ToLower(token.Value)
		if token.Type == lexer.TokenShellCommand && isInlineInterpreterExecution(tokens, i, lower) && hasDownload {
			return []rules.Finding{{
				Message:  "Network download command piped to shell interpreter",
				Position: token.Position,
			}}
		}
		if !isPowerShellExecSignal(lower) {
			continue
		}
		if hasDownload {
			return []rules.Finding{{
				Message:  "Network download command piped to shell interpreter",
				Position: token.Position,
			}}
		}
	}

	return nil
}

func isDownloadSignal(token rules.Token, lower string) bool {
	if _, ok := signals.DownloadCommands[lower]; ok {
		return true
	}
	return token.Type == lexer.TokenWord && (lower == "downloadstring" || lower == "downloadfile")
}

func hasPipeToInterpreter(tokens []rules.Token, start int) bool {
	pipeIndex := findPipeAhead(tokens, start)
	if pipeIndex == -1 {
		return false
	}

	next := nextInterpreterCandidate(tokens, pipeIndex+1)
	if next == nil {
		return false
	}
	_, ok := signals.ShellInterpreters[strings.ToLower(next.Value)]
	return ok
}

func hasPipeToPowerShellExec(tokens []rules.Token, start int) bool {
	pipeIndex := findPipeAhead(tokens, start)
	if pipeIndex == -1 {
		return false
	}

	next := nextInterpreterCandidate(tokens, pipeIndex+1)
	if next == nil {
		return false
	}
	return isPowerShellExecSignal(strings.ToLower(next.Value))
}

func findPipeAhead(tokens []rules.Token, start int) int {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace {
			continue
		}
		if token.Type == lexer.TokenNewline {
			next := nextSignificantToken(tokens, i+1)
			if next != nil && next.Value == "|" {
				continue
			}
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

func isInlineInterpreterExecution(tokens []rules.Token, commandIndex int, lower string) bool {
	if _, ok := signals.ShellInterpreters[lower]; !ok {
		return false
	}
	for i := commandIndex + 1; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		if token.Value == ";" {
			return false
		}
		if token.Value == "-" {
			next := nextSignificantToken(tokens, i+1)
			if next == nil {
				return false
			}
			flag := strings.ToLower(next.Value)
			return flag == "c" || flag == "command" || flag == "encodedcommand"
		}
		if strings.HasPrefix(strings.ToLower(token.Value), "-") {
			flag := strings.TrimLeft(strings.ToLower(token.Value), "-")
			return flag == "c" || flag == "command" || flag == "encodedcommand"
		}
		return false
	}
	return false
}

func isPowerShellExecSignal(lower string) bool {
	return lower == "invoke-expression" || lower == "iex"
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

func nextInterpreterCandidate(tokens []rules.Token, start int) *rules.Token {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}

		lower := strings.ToLower(token.Value)
		if lower == "sudo" || lower == "env" {
			continue
		}
		if next, ok := envAssignmentEnd(tokens, i); ok {
			i = next - 1
			continue
		}

		return &tokens[i]
	}
	return nil
}

func envAssignmentEnd(tokens []rules.Token, start int) (int, bool) {
	if tokens[start].Type != lexer.TokenWord {
		return 0, false
	}

	equalsIndex := nextSignificantTokenIndex(tokens, start+1)
	if equalsIndex == -1 || tokens[equalsIndex].Value != "=" {
		return 0, false
	}

	end := equalsIndex + 1
	for end < len(tokens) {
		token := tokens[end]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			return end, true
		}
		if token.Value == ";" || token.Value == "|" {
			return end, true
		}
		end++
	}

	return end, true
}

func nextSignificantTokenIndex(tokens []rules.Token, start int) int {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}
		return i
	}

	return -1
}
