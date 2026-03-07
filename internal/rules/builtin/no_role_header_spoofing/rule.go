package noroleheaderspoofing

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-role-header-spoofing"
	name        = "No Role Header Spoofing"
	summary     = "Detects structured role-header spoof patterns"
	description = "Role header prefixes such as SYSTEM: or DEVELOPER: can be used to spoof higher-priority instruction channels in prompts."
)

// Rule detects role header spoofing markers.
type Rule struct{}

// New returns the no-role-header-spoofing rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-role-header-spoofing rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-role-header-spoofing rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckSegment detects role-like header prefixes at line starts.
func (Rule) CheckSegment(_ rules.Context, segment rules.Segment) []rules.Finding {
	lower := strings.ToLower(segment.Content)
	match := signals.RoleHeaderPattern.FindStringIndex(lower)
	if match == nil {
		return nil
	}

	return []rules.Finding{{
		Message:  "Structured role header spoofing pattern detected",
		Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, match[0]),
	}}
}
