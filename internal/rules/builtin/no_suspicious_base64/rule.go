package nosuspiciousbase64

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id                = "no-suspicious-base64"
	name              = "No Suspicious Base64 Payload"
	summary           = "Detects long base64-like payloads"
	description       = "Long inline base64 payloads can hide executable or exfiltration content from casual review."
	minimumPayloadLen = 40
)

// Rule detects suspicious base64 payloads in tokenized content.
type Rule struct{}

// New returns the no-suspicious-base64 rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-suspicious-base64 rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-suspicious-base64 rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckTokens detects long base64-like tokens.
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for _, token := range tokens {
		if token.Type != lexer.TokenBase64 {
			continue
		}
		if len(token.Value) < minimumPayloadLen {
			continue
		}
		findings = append(findings, rules.Finding{
			Message:  "Suspicious base64-like payload detected",
			Position: token.Position,
		})
	}
	return findings
}
