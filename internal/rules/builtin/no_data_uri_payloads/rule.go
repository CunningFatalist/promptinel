package nodatauripayloads

import (
	"regexp"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-data-uri-payloads"
	name        = "No Data URI Payloads"
	summary     = "Detects embedded base64 data URI payloads"
	description = "Large embedded data URIs can hide executable or exfiltration payloads in prompt content."
)

var dataURIBase64Pattern = regexp.MustCompile(`(?i)data:(?:[^\s;,]+(?:;[^\s;,=]+=[^\s;,]+)*)?;base64,[a-z0-9+/=]{128,}`)

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
	location := dataURIBase64Pattern.FindStringIndex(doc.Content)
	if len(location) != 2 {
		return nil
	}

	value := doc.Content[location[0]:location[1]]
	comma := strings.IndexByte(value, ',')
	if comma < 0 || comma+1 >= len(value) {
		return nil
	}

	return []rules.Finding{{
		Message:  "Embedded base64 data URI payload detected",
		Position: rules.PositionFromByteOffset(doc.Content, location[0]+comma+1),
	}}
}
