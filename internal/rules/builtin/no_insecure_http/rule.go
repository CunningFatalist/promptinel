package noinsecurehttp

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
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
func (Rule) CheckTokens(ctx rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanAccessNetwork() {
		return nil
	}

	findings := make([]rules.Finding, 0)
	hasHighRiskContext := hasHighRiskSignal(tokens)
	for _, token := range tokens {
		if token.Type != lexer.TokenURL {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(token.Value), "http://") {
			continue
		}
		message := "Insecure HTTP URL detected"
		if hasHighRiskContext {
			message = "Insecure HTTP URL detected in download or execution flow"
		}
		findings = append(findings, rules.Finding{
			Message:  message,
			Position: token.Position,
		})
	}
	return findings
}

func hasHighRiskSignal(tokens []rules.Token) bool {
	for _, token := range tokens {
		lower := strings.ToLower(token.Value)
		if _, ok := signals.HighRiskHTTPSignals[lower]; ok {
			return true
		}
	}

	return false
}
