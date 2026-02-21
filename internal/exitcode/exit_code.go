package exitcode

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
)

// Code represents process exit codes returned by CLI commands.
type Code int

const (
	// CodePass means no actionable findings were detected.
	CodePass Code = 0
	// CodeWarn means findings exceeded the warn threshold but not fail threshold.
	CodeWarn Code = 1
	// CodeFail means findings exceeded the fail threshold.
	CodeFail Code = 2
)

const (
	severityRankLow    = 1
	severityRankMedium = 2
	severityRankHigh   = 3
)

// Error wraps a non-zero process exit code in an error value.
type Error struct {
	Code Code
}

func (e Error) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// Resolve maps findings and configured policy thresholds to an exit code.
func Resolve(policy config.Policy, findings []engine.FileFinding) Code {
	if len(findings) == 0 {
		return CodePass
	}

	maxSeverity := maxFindingSeverity(findings)

	if severityAtLeast(maxSeverity, policy.FailOn) {
		return CodeFail
	}

	if severityAtLeast(maxSeverity, policy.WarnOn) {
		return CodeWarn
	}

	return CodePass
}

func maxFindingSeverity(findings []engine.FileFinding) config.Severity {
	maxSeverity := config.SeverityLow
	for _, finding := range findings {
		if severityRank(finding.Severity) > severityRank(maxSeverity) {
			maxSeverity = finding.Severity
		}
	}
	return maxSeverity
}

func severityAtLeast(severity config.Severity, threshold config.Severity) bool {
	return severityRank(severity) >= severityRank(threshold)
}

func severityRank(severity config.Severity) int {
	switch severity {
	case config.SeverityHigh:
		return severityRankHigh
	case config.SeverityMedium:
		return severityRankMedium
	default:
		return severityRankLow
	}
}
