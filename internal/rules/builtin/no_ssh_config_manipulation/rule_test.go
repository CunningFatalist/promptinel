package nosshconfigmanipulation

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoSSHConfigManipulation_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-ssh-config-manipulation", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoSSHConfigManipulation_Evaluate_DetectsAuthorizedKeysWrite(t *testing.T) {
	content := "echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "SSH trust store manipulation detected", findings[0].Message)
}

func Test_NoSSHConfigManipulation_Evaluate_IgnoresReadOnlyReference(t *testing.T) {
	content := "cat ~/.ssh/config"
	findings := evaluateRule(t, content)
	assert.Empty(t, findings)
}

func Test_NoSSHConfigManipulation_Evaluate_IgnoresAppendixProse(t *testing.T) {
	content := "In the appendix, explain what ~/.ssh/config controls for SSH client behavior."
	findings := evaluateRule(t, content)
	assert.Empty(t, findings)
}

func Test_NoSSHConfigManipulation_Evaluate_IgnoresWhenFilesystemUnavailable(t *testing.T) {
	content := "echo 'Host *' >> ~/.ssh/config"
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
