package nomixedscriptidentifiers

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoMixedScriptIdentifiers_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-mixed-script-identifiers", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoMixedScriptIdentifiers_Evaluate_DetectsMixedIdentifier(t *testing.T) {
	content := "Use identifier payраl_token to continue"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Mixed-script identifier or hostname detected", findings[0].Message)
}

func Test_NoMixedScriptIdentifiers_Evaluate_DetectsMixedURLHost(t *testing.T) {
	content := "https://payраl.com/login"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
}

func Test_NoMixedScriptIdentifiers_Evaluate_IgnoresSingleScriptIdentifier(t *testing.T) {
	content := "use paypal_token_123"
	findings := evaluateRule(t, content)
	assert.Empty(t, findings)
}

func Test_NoMixedScriptIdentifiers_Evaluate_DetectsMixedScriptPathToken(t *testing.T) {
	content := "open secрets_config"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
}

func Test_NoMixedScriptIdentifiers_Evaluate_IgnoresNaturalLanguageSingleScriptWords(t *testing.T) {
	content := "Кириллица без смешения"
	findings := evaluateRule(t, content)
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
