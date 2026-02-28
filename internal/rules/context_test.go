package rules

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/stretchr/testify/assert"
)

func Test_Rules_Context_CapabilityPredicates(t *testing.T) {
	ctx := Context{
		Environment: config.Environment{
			CanExecuteShell:     true,
			CanAccessFilesystem: false,
			CanAccessNetwork:    true,
			HasSecrets:          false,
		},
		TrustLevel: config.TrustLevelTrusted,
	}

	assert.True(t, ctx.CanExecuteShell())
	assert.False(t, ctx.CanAccessFilesystem())
	assert.True(t, ctx.CanAccessNetwork())
	assert.False(t, ctx.HasSecrets())
}

func Test_Rules_Context_IsUntrusted(t *testing.T) {
	assert.False(t, Context{TrustLevel: config.TrustLevelTrusted}.IsUntrusted())
	assert.True(t, Context{TrustLevel: config.TrustLevelUntrusted}.IsUntrusted())
	assert.True(t, Context{TrustLevel: config.TrustLevelTainted}.IsUntrusted())
}
