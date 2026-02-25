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

func evaluateRule(t *testing.T, content string) []rules.Finding {
	t.Helper()

	registry := rules.NewRegistry()
	err := registry.Register(New())
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	return rules.Evaluate(compiled, rules.Context{}, content)
}
