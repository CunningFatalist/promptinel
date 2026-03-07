package nounsafetemplates

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-unsafe-templates"
	name        = "No Unsafe Templates"
	summary     = "Detects risky template expressions with execution or exfiltration intent"
	description = "Template expressions that invoke command, environment, or network-related operations increase prompt execution risk."
)

// Rule detects unsafe signals in template segments.
type Rule struct{}

// New returns the no-unsafe-templates rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-unsafe-templates rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-unsafe-templates rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckTokens scans template token streams for unsafe execution signals.
func (Rule) CheckTokens(_ rules.Context, segment rules.Segment, _ []rules.Token) []rules.Finding {
	if segment.Type != rules.SegmentTypeTemplate {
		return nil
	}
	if !containsUnsafeSignal(innerTemplateTokens(segment.Content)) {
		return nil
	}

	return []rules.Finding{{
		Message:  "Unsafe template expression detected",
		Position: segment.Position,
	}}
}

func containsUnsafeSignal(tokens []rules.Token) bool {
	for i := range tokens {
		token := tokens[i]
		lower := strings.ToLower(token.Value)

		if token.Type == lexer.TokenPlaceholder {
			continue
		}
		if _, ok := signals.UnsafeTemplateSinks[lower]; !ok && !isUnsafeQualifiedWord(lower) {
			continue
		}

		if hasDynamicTemplateOperand(tokens, i) {
			return true
		}
	}

	return false
}

func innerTemplateTokens(value string) []rules.Token {
	inner := unwrapTemplateExpression(value)
	if inner == "" {
		return nil
	}

	lexed := lexer.Classify(lexer.Lex(inner))
	tokens := make([]rules.Token, 0, len(lexed))
	for _, token := range lexed {
		tokens = append(tokens, rules.Token{
			Type:  token.Type,
			Value: token.Value,
			Start: token.Start,
			End:   token.End,
		})
	}

	return tokens
}

func hasDynamicTemplateOperand(tokens []rules.Token, sinkIndex int) bool {
	for i := max(0, sinkIndex-4); i < min(len(tokens), sinkIndex+8); i++ {
		if i == sinkIndex {
			continue
		}

		token := tokens[i]
		switch token.Type {
		case lexer.TokenPlaceholder:
			return true
		case lexer.TokenURL:
			if strings.Contains(token.Value, "${") || strings.Contains(token.Value, "{{") || strings.Contains(token.Value, "<%") {
				return true
			}
		case lexer.TokenWord:
			lower := strings.ToLower(token.Value)
			if _, ok := signals.UnsafeTemplateSafeIdentifiers[lower]; ok {
				continue
			}
			if isDynamicIdentifier(lower) {
				return true
			}
		}
	}

	return false
}

func isDynamicIdentifier(lower string) bool {
	for _, hint := range signals.UnsafeTemplateDynamicIdentifierHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}

	return false
}

func isUnsafeQualifiedWord(lower string) bool {
	return lower == "process.env" ||
		strings.HasPrefix(lower, "process.env.") ||
		strings.HasPrefix(lower, "os.")
}

func unwrapTemplateExpression(value string) string {
	switch {
	case strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}"):
		return strings.TrimSpace(value[2 : len(value)-2])
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		return strings.TrimSpace(value[2 : len(value)-1])
	case strings.HasPrefix(value, "<%") && strings.HasSuffix(value, "%>"):
		return strings.TrimSpace(value[2 : len(value)-2])
	default:
		return strings.TrimSpace(value)
	}
}
