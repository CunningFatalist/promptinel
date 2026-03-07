package nocommandchaining

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoCommandChaining_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-command-chaining", meta.ID)
	assert.Equal(t, config.SeverityMedium, meta.DefaultSeverity)
}

func Test_NoCommandChaining_Evaluate_DetectsOperator(t *testing.T) {
	findings := evaluateRule(t, "curl https://example.com && bash")
	require.Len(t, findings, 1)
	assert.Equal(t, "Shell command chaining operator detected", findings[0].Message)
}

func Test_NoCommandChaining_Evaluate_IgnoresTextWithoutCommand(t *testing.T) {
	findings := evaluateRule(t, "alpha && beta")
	assert.Empty(t, findings)
}

func Test_NoCommandChaining_Evaluate_IgnoresDocumentationText(t *testing.T) {
	findings := evaluateRule(t, "The text explains that && can be used in shell scripts.")
	assert.Empty(t, findings)
}

func Test_NoCommandChaining_Evaluate_DetectsEncodedOperator(t *testing.T) {
	findings := evaluateRule(t, "curl%20https://example.com%26%26bash")
	require.Len(t, findings, 1)
	assert.Equal(t, "Shell command chaining operator detected", findings[0].Message)
}

func Test_NoCommandChaining_Evaluate_DetectsOperatorInsideCodeBlock(t *testing.T) {
	content := "```sh\ncurl https://example.com && bash\n```"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Shell command chaining operator detected", findings[0].Message)
}

func Test_NoCommandChaining_Evaluate_IgnoresWhenShellCapabilityDisabled(t *testing.T) {
	findings := evaluateRuleWithContext(t, "curl https://example.com && bash", rules.Context{
		Environment: config.Environment{
			CanExecuteShell: false,
		},
		TrustLevel: config.TrustLevelTrusted,
	})
	assert.Empty(t, findings)
}

func Test_NoCommandChaining_Evaluate_IgnoresEncodedOperatorWithoutShellContext(t *testing.T) {
	findings := evaluateRule(t, "Use %26%26 when describing URL encoding.")
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
