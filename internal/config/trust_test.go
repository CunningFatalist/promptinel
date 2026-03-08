package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Config_TrustLevelRank(t *testing.T) {
	assert.Equal(t, 0, TrustLevelRank(TrustLevelTrusted))
	assert.Equal(t, 1, TrustLevelRank(TrustLevelUntrusted))
	assert.Equal(t, 2, TrustLevelRank(TrustLevelTainted))
	assert.Equal(t, 0, TrustLevelRank(TrustLevel("unknown")))
}

func Test_Config_MoreRestrictiveTrustLevel(t *testing.T) {
	assert.Equal(t, TrustLevelTrusted, MoreRestrictiveTrustLevel(TrustLevelTrusted, TrustLevelTrusted))
	assert.Equal(t, TrustLevelUntrusted, MoreRestrictiveTrustLevel(TrustLevelTrusted, TrustLevelUntrusted))
	assert.Equal(t, TrustLevelTainted, MoreRestrictiveTrustLevel(TrustLevelUntrusted, TrustLevelTainted))
	assert.Equal(t, TrustLevelTainted, MoreRestrictiveTrustLevel(TrustLevelTainted, TrustLevelTrusted))
}

func Test_Config_TrustLevelAtLeast(t *testing.T) {
	assert.True(t, TrustLevelAtLeast(TrustLevelTrusted, TrustLevelTrusted))
	assert.True(t, TrustLevelAtLeast(TrustLevelUntrusted, TrustLevelTrusted))
	assert.True(t, TrustLevelAtLeast(TrustLevelTainted, TrustLevelUntrusted))
	assert.False(t, TrustLevelAtLeast(TrustLevelTrusted, TrustLevelUntrusted))
}
