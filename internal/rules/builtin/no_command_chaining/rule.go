package nocommandchaining

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
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

	if finding := detectChainingTokens(tokens); finding != nil {
		return finding
	}

	for _, token := range tokens {
		if token.Type != lexer.TokenCodeBlock {
			continue
		}
		if offset, ok := detectCodeBlockChaining(token.Value); ok {
			return []rules.Finding{{
				Message:  "Shell command chaining operator detected",
				Position: helpers.AdvancePositionByByteOffset(token.Position, token.Value, offset),
			}}
		}
	}

	return nil
}

// CheckSegment detects URL-encoded chaining operators when they still appear in shell execution context.
func (Rule) CheckSegment(ctx rules.Context, segment rules.Segment) []rules.Finding {
	if !ctx.CanExecuteShell() {
		return nil
	}

	if offset, ok := detectEncodedChaining(segment.Content); ok {
		return []rules.Finding{{
			Message:  "Shell command chaining operator detected",
			Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, offset),
		}}
	}

	return nil
}

func detectChainingTokens(tokens []rules.Token) []rules.Finding {
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

func detectCodeBlockChaining(codeBlock string) (int, bool) {
	content, innerOffset, ok := unwrapCodeBlock(codeBlock)
	if !ok {
		return 0, false
	}

	lexed := lexer.Classify(lexer.Lex(content))
	innerTokens := make([]rules.Token, 0, len(lexed))
	for _, token := range lexed {
		innerTokens = append(innerTokens, rules.Token{
			Type:  token.Type,
			Value: token.Value,
			Start: token.Start,
			End:   token.End,
		})
	}

	offset, ok := firstChainingTokenOffset(innerTokens)
	if !ok {
		return 0, false
	}

	return innerOffset + offset, true
}

func unwrapCodeBlock(codeBlock string) (string, int, bool) {
	if !strings.HasPrefix(codeBlock, "```") || !strings.HasSuffix(codeBlock, "```") {
		return "", 0, false
	}

	start := 3
	if newline := strings.IndexByte(codeBlock[start:], '\n'); newline >= 0 {
		start += newline + 1
	}
	end := len(codeBlock) - 3
	if end < start {
		return "", 0, false
	}

	return codeBlock[start:end], start, true
}

func detectEncodedChaining(content string) (int, bool) {
	lower := strings.ToLower(content)
	lines := strings.SplitAfter(lower, "\n")
	offset := 0

	for _, line := range lines {
		for _, operator := range signals.EncodedChainingOperators {
			index := strings.Index(line, operator)
			if index == -1 {
				continue
			}
			if hasShellContext(line) {
				return offset + index, true
			}
		}
		offset += len(line)
	}

	return 0, false
}

func firstChainingTokenOffset(tokens []rules.Token) (int, bool) {
	for i := range tokens {
		token := tokens[i]
		if token.Value == ";" && isChainedCommand(tokens, i, i+1) {
			return token.Start, true
		}
		if i+1 >= len(tokens) {
			continue
		}
		if token.Value == "&" && tokens[i+1].Value == "&" && isChainedCommand(tokens, i, i+2) {
			return token.Start, true
		}
		if token.Value == "|" && tokens[i+1].Value == "|" && isChainedCommand(tokens, i, i+2) {
			return token.Start, true
		}
	}

	return 0, false
}

func hasShellContext(line string) bool {
	lexed := lexer.Classify(lexer.Lex(line))
	for _, token := range lexed {
		if token.Type == lexer.TokenShellCommand || token.Type == lexer.TokenURL {
			return true
		}
		if token.Type != lexer.TokenWord {
			continue
		}
		if _, ok := signals.EncodedCommandContextWords[strings.ToLower(token.Value)]; ok {
			return true
		}
	}

	return false
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
