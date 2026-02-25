package noinsecurehttp

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-insecure-http"
	name        = "No Insecure HTTP URL"
	summary     = "Detects plaintext HTTP URLs"
	description = "HTTP URLs can be tampered with in transit and are risky when prompts retrieve executable instructions."
)

// Rule detects plaintext HTTP URLs.
type Rule struct{}

// New returns the no-insecure-http rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-insecure-http rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-insecure-http rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityLow,
	}
}

// CheckTokens detects plaintext HTTP URLs.
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for _, token := range tokens {
		if token.Type != lexer.TokenURL {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(token.Value), "http://") {
			continue
		}
		findings = append(findings, rules.Finding{
			Message:  "Insecure HTTP URL detected",
			Position: token.Position,
		})
	}
	return findings
}
