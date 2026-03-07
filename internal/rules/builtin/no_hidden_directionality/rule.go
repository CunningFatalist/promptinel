package nohiddendirectionality

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
)

const (
	id          = "no-hidden-directionality"
	name        = "No Hidden Directionality"
	summary     = "Detects hidden RTL/LTR controls inside identifier-like tokens"
	description = "Directionality controls inside URLs, paths, and similar tokens can disguise the true rendered order of high-risk prompt content."
)

// Rule detects suspicious directionality usage inside non-natural-language tokens.
type Rule struct{}

// New returns the no-hidden-directionality rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-hidden-directionality rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-hidden-directionality rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckDocument detects directionality controls embedded in identifier-like tokens.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for offset, r := range doc.Content {
		detail, ok := helpers.BidiControlInfo(r)
		if !ok {
			continue
		}

		token, _, _ := helpers.SurroundingNonWhitespaceToken(doc.Content, offset)
		if !helpers.LooksIdentifierLikeValue(token) {
			continue
		}

		findings = append(findings, rules.Finding{
			Message:  fmt.Sprintf("Hidden directionality marker detected inside identifier-like token (%s)", detail.Name),
			Position: rules.PositionFromByteOffset(doc.Content, offset),
		})
	}

	return findings
}
