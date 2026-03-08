package notaintedplaceholderinstructions

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-tainted-placeholder-instructions"
	name        = "No Tainted Placeholder Instructions"
	summary     = "Detects tainted placeholders near override or capability language"
	description = "Untrusted placeholders placed next to override, execution, or capability language can act as injection boundaries and should be treated as high risk."
)

// Rule detects suspicious tainted placeholders near execution-oriented language.
type Rule struct{}

// New returns the no-tainted-placeholder-instructions rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-tainted-placeholder-instructions rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-tainted-placeholder-instructions rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckDocument detects untrusted placeholders placed next to override or capability signals.
func (Rule) CheckDocument(ctx rules.Context, doc rules.DocumentView) []rules.Finding {
	matches := signals.PlaceholderPattern.FindAllStringIndex(doc.Content, -1)
	for _, match := range matches {
		if !ctx.IsUntrustedRange(match[0], match[1]) {
			continue
		}

		windowStart := max(0, match[0]-72)
		windowEnd := min(len(doc.Content), match[1]+72)
		window := strings.ToLower(doc.Content[windowStart:windowEnd])
		if hasPlaceholderInstructionSignal(window) {
			return []rules.Finding{{
				Message:  "Tainted placeholder used near override or capability instructions detected",
				Position: rules.PositionFromByteOffset(doc.Content, match[0]),
			}}
		}
	}

	return nil
}

func hasPlaceholderInstructionSignal(window string) bool {
	if containsAny(window, signals.OverridePhrases) || containsAny(window, signals.UntrustedOverridePhrases) {
		return true
	}
	return containsAny(window, signals.PlaceholderCapabilitySignals)
}

func containsAny(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}
	return false
}
