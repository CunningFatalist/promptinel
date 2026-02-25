package nodatauripayloads

import (
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Builtin_NoDataURIPayloads_DetectsLongBase64DataURI(t *testing.T) {
	payload := strings.Repeat("A", 128)
	content := "prefix data:text/plain;base64," + payload
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Embedded base64 data URI payload detected", findings[0].Message)
	assert.Equal(t, rules.Position{Line: 1, Column: 31}, findings[0].Position)
}

func Test_Builtin_NoDataURIPayloads_IgnoresShortDataURI(t *testing.T) {
	content := "data:text/plain;base64,QUJD"
	findings := evaluateRule(t, content)
	assert.Empty(t, findings)
}

func Test_Builtin_NoDataURIPayloads_DetectsLongBase64DataURIWithParameters(t *testing.T) {
	payload := strings.Repeat("A", 128)
	content := "data:text/plain;charset=utf-8;base64," + payload
	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Embedded base64 data URI payload detected", findings[0].Message)
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
