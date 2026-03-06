package nointerpreterinlineexec

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoInterpreterInlineExec_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-interpreter-inline-exec", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoInterpreterInlineExec_Evaluate_DetectsPythonInlineExec(t *testing.T) {
	findings := evaluateRule(t, "python -c \"print(1)\"")
	require.Len(t, findings, 1)
	assert.Equal(t, "Inline interpreter execution flag detected", findings[0].Message)
}

func Test_NoInterpreterInlineExec_Evaluate_IgnoresInterpreterWithoutInlineFlag(t *testing.T) {
	findings := evaluateRule(t, "python script.py")
	assert.Empty(t, findings)
}

func Test_NoInterpreterInlineExec_Evaluate_IgnoresNonInlineFlag(t *testing.T) {
	findings := evaluateRule(t, "python -m pip install requests")
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
