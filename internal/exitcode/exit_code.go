package exitcode

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/finding"
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

// Error wraps a non-zero process exit code in an error value.
type Error struct {
	Code Code
}

func (e Error) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// Resolve maps findings and configured policy thresholds to an exit code.
func Resolve(policy config.Policy, findings []finding.FileFinding) Code {
	if len(findings) == 0 {
		return CodePass
	}

	maxSeverity := maxFindingSeverity(findings)

	if config.SeverityAtLeast(maxSeverity, policy.FailOn) {
		return CodeFail
	}

	if config.SeverityAtLeast(maxSeverity, policy.WarnOn) {
		return CodeWarn
	}

	return CodePass
}

func maxFindingSeverity(findings []finding.FileFinding) config.Severity {
	maxSeverity := config.SeverityLow
	for _, finding := range findings {
		if config.SeverityRank(finding.Severity) > config.SeverityRank(maxSeverity) {
			maxSeverity = finding.Severity
		}
	}
	return maxSeverity
}
