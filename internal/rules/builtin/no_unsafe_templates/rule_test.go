package nounsafetemplates

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoUnsafeTemplates_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-unsafe-templates", meta.ID)
	assert.Equal(t, config.SeverityMedium, meta.DefaultSeverity)
}

func Test_NoUnsafeTemplates_Evaluate_DetectsUnsafeTemplateExpression(t *testing.T) {
	content := "before\n{{ exec(command_input) }}\nafter"

	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Unsafe template expression detected", findings[0].Message)
	assert.Equal(t, 2, findings[0].Position.Line)
	assert.Equal(t, 1, findings[0].Position.Column)
}

func Test_NoUnsafeTemplates_Evaluate_IgnoresSafeTemplateExpression(t *testing.T) {
	findings := evaluateRule(t, "{{ user_name }}")
	assert.Empty(t, findings)
}

func Test_NoUnsafeTemplates_Evaluate_IgnoresCommonBenignWords(t *testing.T) {
	content := "{{ environment }} {{ command_name }} {{ envelope }}"
	findings := evaluateRule(t, content)
	assert.Empty(t, findings)
}

func Test_NoUnsafeTemplates_Evaluate_DetectsProcessEnvAccess(t *testing.T) {
	content := "{{ fetch(process.env.API_URL) }}"
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Unsafe template expression detected", findings[0].Message)
}

func Test_NoUnsafeTemplates_Evaluate_IgnoresStaticLiteralExecutionSnippet(t *testing.T) {
	findings := evaluateRule(t, "{{ exec(\"echo hello\") }}")
	assert.Empty(t, findings)
}

func evaluateRule(t *testing.T, content string) []rules.Finding {
	t.Helper()

	registry := rules.NewRegistry()
	err := registry.Register(New())
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	return rules.Evaluate(compiled, rules.Context{}, content)
}
