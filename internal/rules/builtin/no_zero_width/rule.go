package nozerowidth

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-zero-width"
	name        = "No Zero Width Characters"
	summary     = "Detects hidden zero-width Unicode characters"
	description = "Invisible zero-width characters can hide instructions and make reviews unreliable."
)

// Rule detects zero-width characters in tokenized content.
type Rule struct{}

// New returns the no-zero-width rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-zero-width rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-zero-width rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckTokens detects zero-width tokens in segments.
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for _, token := range tokens {
		if token.Type != lexer.TokenZeroWidth {
			continue
		}
		findings = append(findings, rules.Finding{
			Message:  "Zero-width character detected",
			Position: token.Position,
		})
	}
	return findings
}
