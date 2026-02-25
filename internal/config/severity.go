package config

const (
	severityRankLow    = 1
	severityRankMedium = 2
	severityRankHigh   = 3
)

// SeverityRank returns the comparable rank for a severity value.
func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return severityRankHigh
	case SeverityMedium:
		return severityRankMedium
	default:
		return severityRankLow
	}
}

// SeverityAtLeast reports whether severity is greater than or equal to threshold.
func SeverityAtLeast(severity Severity, threshold Severity) bool {
	return SeverityRank(severity) >= SeverityRank(threshold)
}
