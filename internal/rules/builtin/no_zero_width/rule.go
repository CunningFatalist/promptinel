package nozerowidth

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-zero-width"
	name        = "No Zero Width Characters"
	summary     = "Detects hidden zero-width Unicode characters"
	description = "Invisible zero-width characters can hide instructions and make reviews unreliable."
)

// Rule detects zero-width characters in full document content.
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

// CheckDocument detects zero-width characters in content.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	content := doc.Content
	findings := make([]rules.Finding, 0)
	for i, candidate := range content {
		if !isZeroWidth(candidate) {
			continue
		}
		findings = append(findings, rules.Finding{
			Message:  "Zero-width character detected",
			Position: rules.PositionFromByteOffset(content, i),
		})
	}
	return findings
}

func isZeroWidth(r rune) bool {
	return strings.ContainsRune("\u200B\u200C\u200D\u2060\uFEFF", r)
}
