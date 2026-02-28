package nometadataserviceaccess

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoMetadataServiceAccess_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-metadata-service-access", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoMetadataServiceAccess_Evaluate_DetectsMetadataURL(t *testing.T) {
	findings := evaluateRule(t, "curl http://169.254.169.254/latest/meta-data/iam")
	require.Len(t, findings, 1)
	assert.Equal(t, "Cloud metadata service URL detected", findings[0].Message)
}

func Test_NoMetadataServiceAccess_Evaluate_IgnoresRegularURL(t *testing.T) {
	findings := evaluateRule(t, "curl https://example.com")
	assert.Empty(t, findings)
}

func Test_NoMetadataServiceAccess_Evaluate_DetectsMetadataURLWithTrailingDot(t *testing.T) {
	findings := evaluateRule(t, "curl http://metadata.google.internal./computeMetadata/v1")
	require.Len(t, findings, 1)
	assert.Equal(t, "Cloud metadata service URL detected", findings[0].Message)
}

func Test_NoMetadataServiceAccess_Evaluate_IgnoresWhenNetworkDisabled(t *testing.T) {
	findings := evaluateRuleWithContext(t, "curl http://169.254.169.254/latest/meta-data/iam", rules.Context{
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
