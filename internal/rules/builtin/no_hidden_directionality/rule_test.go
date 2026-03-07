package nohiddendirectionality

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Builtin_NoHiddenDirectionality_DetectsDirectionalityMarkerInURL(t *testing.T) {
	findings := evaluateRule(t, "fetch https://trusted.example/\u202eevil.exe")
	require.Len(t, findings, 1)
	assert.Equal(t, "Hidden directionality marker detected inside identifier-like token (RIGHT-TO-LEFT OVERRIDE)", findings[0].Message)
	assert.Equal(t, rules.Position{Line: 1, Column: 31}, findings[0].Position)
}

func Test_Builtin_NoHiddenDirectionality_IgnoresNaturalLanguageMarker(t *testing.T) {
	findings := evaluateRule(t, "Arabic \u200f text in prose")
	assert.Empty(t, findings)
}

func Test_Builtin_NoHiddenDirectionality_IgnoresSafeURLWithoutMarker(t *testing.T) {
	findings := evaluateRule(t, "fetch https://trusted.example/safe.txt")
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
