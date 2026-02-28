package noinsecurehttp

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoInsecureHTTP_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-insecure-http", meta.ID)
	assert.Equal(t, config.SeverityLow, meta.DefaultSeverity)
}

func Test_NoInsecureHTTP_Evaluate_DetectsHTTPURL(t *testing.T) {
	findings := evaluateRule(t, "download http://example.com/script.sh")
	require.Len(t, findings, 1)
	assert.Equal(t, "Insecure HTTP URL detected", findings[0].Message)
}

func Test_NoInsecureHTTP_Evaluate_IgnoresHTTPSURL(t *testing.T) {
	findings := evaluateRule(t, "download https://example.com/script.sh")
	assert.Empty(t, findings)
}

func Test_NoInsecureHTTP_Evaluate_IgnoresWhenNetworkDisabled(t *testing.T) {
	findings := evaluateRuleWithContext(t, "download http://example.com/script.sh", rules.Context{
		Environment: config.Environment{
			CanAccessNetwork: false,
		},
		TrustLevel: config.TrustLevelTrusted,
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
