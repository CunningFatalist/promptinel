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

func evaluateRule(t *testing.T, content string) []rules.Finding {
	t.Helper()

	registry := rules.NewRegistry()
	err := registry.Register(New())
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	return rules.Evaluate(compiled, rules.Context{}, content)
}
