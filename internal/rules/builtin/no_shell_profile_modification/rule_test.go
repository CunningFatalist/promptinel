package noshellprofilemodification

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoShellProfileModification_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-shell-profile-modification", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoShellProfileModification_Evaluate_DetectsProfilePersistence(t *testing.T) {
	content := "echo 'alias ll=ls -la' >> ~/.bashrc"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Shell profile modification attempt detected", findings[0].Message)
}

func Test_NoShellProfileModification_Evaluate_IgnoresProfileReferenceWithoutWriteIntent(t *testing.T) {
	content := "Read ~/.bashrc to inspect aliases"
	findings := evaluateRule(t, content)
	assert.Empty(t, findings)
}

func Test_NoShellProfileModification_Evaluate_IgnoresWhenFilesystemUnavailable(t *testing.T) {
	content := "echo 'export MAL=1' >> ~/.zshrc"
	findings := evaluateRuleWithContext(t, content, rules.Context{
		Environment: config.Environment{CanAccessFilesystem: false},
		TrustLevel:  config.TrustLevelTrusted,
	})
	assert.Empty(t, findings)
}

func evaluateRule(t *testing.T, content string) []rules.Finding {
	return evaluateRuleWithContext(t, content, defaultRuleContext())
}

func evaluateRuleWithContext(t *testing.T, content string, ctx rules.Context) []rules.Finding {
	t.Helper()

	registry := rules.NewRegistry()
	err := registry.Register(New())
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	return rules.Evaluate(compiled, ctx, content)
}

func defaultRuleContext() rules.Context {
	return rules.Context{
		Environment: config.Environment{
			CanExecuteShell:     true,
			CanAccessFilesystem: true,
			CanAccessNetwork:    true,
			HasSecrets:          true,
		},
		TrustLevel: config.TrustLevelTrusted,
	}
}
