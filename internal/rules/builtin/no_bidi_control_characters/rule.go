package nobidicontrolcharacters

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-bidi-control-characters"
	name        = "No Bidi Control Characters"
	summary     = "Detects bidirectional text control characters"
	description = "Bidi control characters can visually reorder instructions and hide malicious intent in prompt text."
)

var bidiControlRunes = map[rune]struct{}{
	'\u200e': {}, // LEFT-TO-RIGHT MARK
	'\u200f': {}, // RIGHT-TO-LEFT MARK
	'\u202a': {}, // LEFT-TO-RIGHT EMBEDDING
	'\u202b': {}, // RIGHT-TO-LEFT EMBEDDING
	'\u202c': {}, // POP DIRECTIONAL FORMATTING
	'\u202d': {}, // LEFT-TO-RIGHT OVERRIDE
	'\u202e': {}, // RIGHT-TO-LEFT OVERRIDE
	'\u2066': {}, // LEFT-TO-RIGHT ISOLATE
	'\u2067': {}, // RIGHT-TO-LEFT ISOLATE
	'\u2068': {}, // FIRST STRONG ISOLATE
	'\u2069': {}, // POP DIRECTIONAL ISOLATE
}

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
	for offset, r := range doc.Content {
		if _, ok := bidiControlRunes[r]; !ok {
			continue
		}

		return []rules.Finding{{
			Message:  "Bidirectional control character detected",
			Position: rules.PositionFromByteOffset(doc.Content, offset),
		}}
	}

	return nil
}
