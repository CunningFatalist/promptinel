package nopromptinjectionoverride

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-prompt-injection-override"
	name        = "No Prompt Override Instructions"
	summary     = "Detects common prompt-injection override phrases"
	description = "Instruction-override language often appears in prompt-injection attempts designed to bypass system and developer controls."
)

// Rule detects prompt-injection override phrases.
type Rule struct{}

// New returns the no-prompt-injection-override rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-prompt-injection-override rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-prompt-injection-override rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckSegment detects common instruction override phrases.
func (Rule) CheckSegment(_ rules.Context, segment rules.Segment) []rules.Finding {
	lower := strings.ToLower(segment.Content)
	for _, phrase := range signals.OverridePhrases {
		index := strings.Index(lower, phrase)
		if index == -1 {
			continue
		}
		return []rules.Finding{{
			Message:  "Prompt instruction override phrase detected",
			Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index),
		}}
	}

	return nil
}
