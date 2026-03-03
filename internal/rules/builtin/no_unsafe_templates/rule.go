package nounsafetemplates

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-unsafe-templates"
	name        = "No Unsafe Templates"
	summary     = "Detects risky template expressions with execution or exfiltration intent"
	description = "Template expressions that invoke command, environment, or network-related operations increase prompt execution risk."
)

var unsafeTokenWords = map[string]struct{}{
	"exec":     {},
	"execute":  {},
	"system":   {},
	"getenv":   {},
	"readfile": {},
	"open":     {},
}

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
func (Rule) CheckTokens(_ rules.Context, segment rules.Segment, tokens []rules.Token) []rules.Finding {
	if segment.Type != rules.SegmentTypeTemplate {
		return nil
	}
	if !containsUnsafeSignal(tokens) {
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

		if token.Type == lexer.TokenURL || token.Type == lexer.TokenShellCommand {
			return true
		}
		if token.Type == lexer.TokenPlaceholder {
			if containsUnsafePlaceholder(token.Value) {
				return true
			}
		}

		if _, ok := unsafeTokenWords[lower]; ok {
			return true
		}
		if isUnsafeQualifiedWord(lower) {
			return true
		}

		if lower == "process" && i+2 < len(tokens) &&
			tokens[i+1].Value == "." && strings.EqualFold(tokens[i+2].Value, "env") {
			return true
		}
		if lower == "os" && i+1 < len(tokens) && tokens[i+1].Value == "." {
			return true
		}
	}

	return false
}

func containsUnsafePlaceholder(value string) bool {
	inner := unwrapPlaceholder(value)
	if inner == "" {
		return false
	}

	tokens := lexer.Classify(lexer.Lex(inner))
	ruleTokens := make([]rules.Token, 0, len(tokens))
	for _, token := range tokens {
		ruleTokens = append(ruleTokens, rules.Token{
			Type:  token.Type,
			Value: token.Value,
			Start: token.Start,
			End:   token.End,
		})
	}

	return containsUnsafeSignal(ruleTokens)
}

func isUnsafeQualifiedWord(lower string) bool {
	return lower == "process.env" ||
		strings.HasPrefix(lower, "process.env.") ||
		strings.HasPrefix(lower, "os.")
}

func unwrapPlaceholder(value string) string {
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
