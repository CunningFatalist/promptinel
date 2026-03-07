package nobidicontrolcharacters

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
)

const (
	id          = "no-bidi-control-characters"
	name        = "No Bidi Control Characters"
	summary     = "Detects bidirectional text control characters"
	description = "Bidi control characters can visually reorder instructions and hide malicious intent in prompt text."
)

// Rule detects bidirectional control characters.
type Rule struct{}

// New returns the no-bidi-control-characters rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-bidi-control-characters rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-bidi-control-characters rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckDocument detects bidi control characters in the full document.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for offset, r := range doc.Content {
		detail, ok := helpers.BidiControlInfo(r)
		if !ok {
			continue
		}

		message := fmt.Sprintf("Bidirectional control character detected (%s, %s)", detail.Name, detail.Class)
		if token, _, _ := helpers.SurroundingNonWhitespaceToken(doc.Content, offset); helpers.LooksIdentifierLikeValue(token) {
			message = fmt.Sprintf("%s inside URL/path-like token", message)
		}

		findings = append(findings, rules.Finding{
			Message:  message,
			Position: rules.PositionFromByteOffset(doc.Content, offset),
		})
	}

	return findings
}
