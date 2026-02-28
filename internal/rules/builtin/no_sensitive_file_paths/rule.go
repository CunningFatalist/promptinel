package nosensitivefilepaths

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-sensitive-file-paths"
	name        = "No Sensitive File Paths"
	summary     = "Detects references to commonly targeted sensitive local files"
	description = "Access to credential files, host secrets, or system identity files can indicate prompt-driven data exfiltration intent."
)

// Rule detects references to sensitive local files.
type Rule struct{}

// New returns the no-sensitive-file-paths rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-sensitive-file-paths rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-sensitive-file-paths rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckSegment detects references to sensitive file paths.
func (Rule) CheckSegment(ctx rules.Context, segment rules.Segment) []rules.Finding {
	if !ctx.CanAccessFilesystem() {
		return nil
	}

	lower := strings.ToLower(segment.Content)
	for _, snippet := range signals.SensitivePathSnippets {
		index := strings.Index(lower, snippet)
		if index == -1 {
			continue
		}
		return []rules.Finding{{
			Message:  "Sensitive local file path reference detected",
			Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index),
		}}
	}

	return nil
}
