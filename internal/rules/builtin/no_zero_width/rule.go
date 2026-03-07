package nozerowidth

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
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

// CheckDocument detects invisible formatting runes that can hide prompt content.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for offset, r := range doc.Content {
		detail, ok := helpers.InvisibleFormattingInfo(r)
		if !ok {
			continue
		}

		message := "Zero-width character detected"
		if detail.Class != "zero-width" {
			message = fmt.Sprintf("Zero-width character detected (%s, %s)", detail.Name, detail.Class)
		}
		findings = append(findings, rules.Finding{
			Message:  message,
			Position: rules.PositionFromByteOffset(doc.Content, offset),
		})
	}
	return findings
}
