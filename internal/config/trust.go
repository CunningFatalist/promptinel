package config

const (
	trustRankTrusted = iota
	trustRankUntrusted
	trustRankTainted
)

// TrustLevelRank returns the comparable rank for a trust level.
func TrustLevelRank(level TrustLevel) int {
	switch level {
	case TrustLevelTainted:
		return trustRankTainted
	case TrustLevelUntrusted:
		return trustRankUntrusted
	default:
		return trustRankTrusted
	}
}

// MoreRestrictiveTrustLevel returns the lower-trust of two levels.
func MoreRestrictiveTrustLevel(a TrustLevel, b TrustLevel) TrustLevel {
	if TrustLevelRank(b) > TrustLevelRank(a) {
		return b
	}
	return a
}

// TrustLevelAtLeast reports whether level is at least as restrictive as threshold.
func TrustLevelAtLeast(level TrustLevel, threshold TrustLevel) bool {
	return TrustLevelRank(level) >= TrustLevelRank(threshold)
}
