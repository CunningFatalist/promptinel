package notemplatenetworkfetch

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoTemplateNetworkFetch_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-template-network-fetch", meta.ID)
	assert.Equal(t, config.SeverityMedium, meta.DefaultSeverity)
}

func Test_NoTemplateNetworkFetch_Evaluate_DetectsDynamicFetch(t *testing.T) {
	findings := evaluateRule(t, "{{ fetch(endpoint_url) }}")
	require.Len(t, findings, 1)
	assert.Equal(t, "Dynamic template-driven network fetch detected", findings[0].Message)
}

func Test_NoTemplateNetworkFetch_Evaluate_IgnoresStaticLiteralFetch(t *testing.T) {
	findings := evaluateRule(t, "{{ fetch(\"https://example.com\") }}")
	assert.Empty(t, findings)
}

func Test_NoTemplateNetworkFetch_Evaluate_IgnoresPlainText(t *testing.T) {
	findings := evaluateRule(t, "fetch endpoint_url")
	assert.Empty(t, findings)
}

func Test_NoTemplateNetworkFetch_Evaluate_DetectsPlaceholderDrivenFetch(t *testing.T) {
	findings := evaluateRule(t, "{{ request(${remote_url}) }}")
	require.Len(t, findings, 1)
}

func Test_NoTemplateNetworkFetch_Evaluate_DetectsDynamicHostName(t *testing.T) {
	findings := evaluateRule(t, "{{ http(host_value) }}")
	require.Len(t, findings, 1)
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
