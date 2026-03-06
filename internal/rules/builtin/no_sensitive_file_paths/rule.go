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

	intentWindow = 120
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
	pathIndex := firstSensitivePathIndex(lower)
	if pathIndex == -1 {
		return nil
	}
	if !hasReadOrPersistIntent(lower, pathIndex) {
		return nil
	}

	return []rules.Finding{{
		Message:  "Sensitive local file path reference detected",
		Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, pathIndex),
	}}
}

func firstSensitivePathIndex(content string) int {
	earliest := -1
	for _, snippet := range signals.SensitivePathSnippets {
		index := strings.Index(content, snippet)
		if index == -1 {
			continue
		}
		if earliest == -1 || index < earliest {
			earliest = index
		}
	}
	return earliest
}

func hasReadOrPersistIntent(content string, pathIndex int) bool {
	windowStart := max(0, pathIndex-intentWindow)
	windowEnd := min(len(content), pathIndex+intentWindow)
	window := content[windowStart:windowEnd]

	if containsSignal(window, signals.SensitiveReadIntentSignals) {
		return true
	}
	if containsSignal(window, signals.SensitiveWriteIntentSignals) {
		return true
	}
	return strings.Contains(window, ">>") || strings.Contains(window, " > ")
}

func containsSignal(content string, signalsMap map[string]struct{}) bool {
	for signal := range signalsMap {
		if strings.Contains(content, signal) {
			return true
		}
	}
	return false
}
