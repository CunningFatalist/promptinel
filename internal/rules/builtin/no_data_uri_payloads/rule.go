package nodatauripayloads

import (
	"slices"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-data-uri-payloads"
	name        = "No Data URI Payloads"
	summary     = "Detects embedded base64 data URI payloads"
	description = "Large embedded data URIs can hide executable or exfiltration payloads in prompt content."
)

// Rule detects embedded base64 data URI payloads.
type Rule struct{}

// New returns the no-data-uri-payloads rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-data-uri-payloads rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-data-uri-payloads rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckDocument detects long data URI base64 payloads in the full document.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	matches := signals.DataURIBase64Pattern.FindAllStringSubmatchIndex(doc.Content, -1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		mimeType := strings.ToLower(doc.Content[match[2]:match[3]])
		payload := doc.Content[match[4]:match[5]]
		if !shouldFlagDataURI(mimeType, payload) {
			continue
		}

		return []rules.Finding{{
			Message:  "Embedded base64 data URI payload detected",
			Position: rules.PositionFromByteOffset(doc.Content, match[4]),
		}}
	}

	return nil
}

func shouldFlagDataURI(mimeType string, payload string) bool {
	if mimeType == "" {
		return len(payload) >= 128
	}
	if containsAnyPrefix(mimeType, signals.DataURIBenignMIMEPrefixes) {
		return false
	}
	if containsExact(mimeType, signals.DataURIRiskyMIMEs) {
		return len(payload) >= 32
	}
	return len(payload) >= 128
}

func containsExact(value string, options []string) bool {
	return slices.Contains(options, value)
}

func containsAnyPrefix(value string, options []string) bool {
	for _, option := range options {
		if strings.HasPrefix(value, option) {
			return true
		}
	}
	return false
}
