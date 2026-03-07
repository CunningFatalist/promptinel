package nomultilayerencoding

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Builtin_NoMultilayerEncoding_DetectsStackedEncodedPayloadAndDecodeStep(t *testing.T) {
	content := "payload=U0dWc2JHOGdWMjl5YkdRPQ%3D%3D%0A\npython -c \"import urllib.parse,base64,gzip\""
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Multi-layer encoded payload staging detected", findings[0].Message)
	assert.Equal(t, rules.Position{Line: 1, Column: 31}, findings[0].Position)
}

func Test_Builtin_NoMultilayerEncoding_IgnoresSingleEncodingOnly(t *testing.T) {
	findings := evaluateRule(t, "payload=U0dWc2JHOGdWMjl5YkdRPQ==")
	assert.Empty(t, findings)
}

func Test_Builtin_NoMultilayerEncoding_IgnoresDocumentationWithoutEncodedPayload(t *testing.T) {
	findings := evaluateRule(t, "Base64 and URL encoding are common data formats, and gzip can compress responses.")
	assert.Empty(t, findings)
}

func Test_Builtin_NoMultilayerEncoding_IgnoresBenignProseWithEncodedOperatorExample(t *testing.T) {
	findings := evaluateRule(t, `This doc explains base64 decoding and decodeURIComponent("%24%28") in prose.`)
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
