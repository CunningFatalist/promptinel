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
func (Rule) CheckSegment(ctx rules.Context, segment rules.Segment) []rules.Finding {
	lower := strings.ToLower(segment.Content)
	if index := firstPhraseIndex(lower, signals.OverridePhrases); index >= 0 {
		return []rules.Finding{{
			Message:  "Prompt instruction override phrase detected",
			Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index),
		}}
	}

	if ctx.IsUntrusted() {
		if index := firstPhraseIndex(lower, signals.UntrustedOverridePhrases); index >= 0 {
			return []rules.Finding{{
				Message:  "Prompt instruction override phrase detected",
				Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index),
			}}
		}
	}

	return nil
}

func firstPhraseIndex(content string, phrases []string) int {
	earliest := -1
	for _, phrase := range phrases {
		index := strings.Index(content, phrase)
		if index == -1 {
			continue
		}
		if earliest == -1 || index < earliest {
			earliest = index
		}
	}

	return earliest
}
