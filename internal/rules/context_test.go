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

func Test_Rules_Context_EffectiveTrustRange(t *testing.T) {
	ctx := Context{
		TrustLevel: config.TrustLevelTrusted,
		TrustSpans: []TrustSpan{
			{Start: 6, End: 12, TrustLevel: config.TrustLevelUntrusted, Source: TrustSpanSourceRemoteInclude},
			{Start: 8, End: 10, TrustLevel: config.TrustLevelTainted, Source: TrustSpanSourceUserInputPlaceholder},
		},
	}

	assert.Equal(t, config.TrustLevelTrusted, ctx.EffectiveTrustRange(0, 5))
	assert.Equal(t, config.TrustLevelUntrusted, ctx.EffectiveTrustRange(6, 8))
	assert.Equal(t, config.TrustLevelTainted, ctx.EffectiveTrustRange(8, 9))
	assert.Equal(t, config.TrustLevelTainted, ctx.EffectiveTrustRange(7, 11))
	assert.Equal(t, config.TrustLevelTainted, ctx.EffectiveTrustAt(8))
	assert.Equal(t, config.TrustLevelTrusted, ctx.EffectiveTrustAt(2))
}

func Test_Rules_Context_EffectiveTrustRange_DoesNotRaiseDocumentTrust(t *testing.T) {
	ctx := Context{
		TrustLevel: config.TrustLevelUntrusted,
		TrustSpans: []TrustSpan{
			{Start: 0, End: 4, TrustLevel: config.TrustLevelTrusted, Source: TrustSpanSourceUserInputPlaceholder},
		},
	}

	assert.Equal(t, config.TrustLevelUntrusted, ctx.EffectiveTrustRange(0, 4))
	assert.True(t, ctx.IsUntrustedRange(0, 4))
	assert.False(t, ctx.IsTaintedRange(0, 4))
}

func Test_Rules_Context_HasReferencedSkillResources(t *testing.T) {
	assert.False(t, Context{}.HasReferencedSkillResources())
	assert.False(t, Context{Skill: &SkillContext{}}.HasReferencedSkillResources())
	assert.True(t, Context{Skill: &SkillContext{
		ReferencedResources: []string{"scripts/run.py"},
	}}.HasReferencedSkillResources())
}
