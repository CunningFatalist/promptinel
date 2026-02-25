package nosensitivefilepaths

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoSensitiveFilePaths_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-sensitive-file-paths", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoSensitiveFilePaths_Evaluate_DetectsSensitivePath(t *testing.T) {
	findings := evaluateRule(t, "cat /etc/passwd")
	require.Len(t, findings, 1)
	assert.Equal(t, "Sensitive local file path reference detected", findings[0].Message)
}

func Test_NoSensitiveFilePaths_Evaluate_IgnoresRegularPath(t *testing.T) {
	findings := evaluateRule(t, "cat ./docs/readme.md")
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
