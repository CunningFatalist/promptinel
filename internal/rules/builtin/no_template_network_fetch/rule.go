package notemplatenetworkfetch

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-template-network-fetch"
	name        = "No Template Network Fetch"
	summary     = "Detects dynamic network or tool fetch behavior in templates"
	description = "Template expressions that dynamically construct network fetches or tool invocations can turn untrusted data into external actions."
)

// Rule detects dynamic template-driven fetch behavior.
type Rule struct{}

// New returns the no-template-network-fetch rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-template-network-fetch rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-template-network-fetch rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckTokens detects network fetch terms that are driven by placeholders or dynamic identifiers.
func (Rule) CheckTokens(_ rules.Context, segment rules.Segment, _ []rules.Token) []rules.Finding {
	if segment.Type != rules.SegmentTypeTemplate {
		return nil
	}

	tokens := innerTemplateTokens(segment.Content)
	for i, token := range tokens {
		lower := strings.ToLower(token.Value)
		if _, ok := signals.TemplateFetchTerms[lower]; !ok && token.Type != lexer.TokenURL {
			continue
		}
		if hasDynamicNetworkOperand(tokens, i) {
			return []rules.Finding{{
				Message:  "Dynamic template-driven network fetch detected",
				Position: segment.Position,
			}}
		}
	}

	return nil
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

func hasDynamicNetworkOperand(tokens []rules.Token, sinkIndex int) bool {
	for i := max(0, sinkIndex-4); i < min(len(tokens), sinkIndex+8); i++ {
		if i == sinkIndex {
			continue
		}
		token := tokens[i]
		switch token.Type {
		case lexer.TokenPlaceholder:
			return true
		case lexer.TokenWord:
			lower := strings.ToLower(token.Value)
			for _, hint := range signals.TemplateNetworkIdentifierHints {
				if strings.Contains(lower, hint) {
					return true
				}
			}
		case lexer.TokenURL:
			if strings.Contains(token.Value, "${") || strings.Contains(token.Value, "{{") || strings.Contains(token.Value, "<%") {
				return true
			}
		}
	}
	return false
}
