package nobidicontrolcharacters

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Builtin_NoBidiControlCharacters_DetectsBidiRune(t *testing.T) {
	findings := evaluateRule(t, "safe text \u202Ehidden")
	require.Len(t, findings, 1)
	assert.Equal(t, "Bidirectional control character detected (RIGHT-TO-LEFT OVERRIDE, override)", findings[0].Message)
	assert.Equal(t, rules.Position{Line: 1, Column: 11}, findings[0].Position)
}

func Test_Builtin_NoBidiControlCharacters_IgnoresNormalText(t *testing.T) {
	findings := evaluateRule(t, "safe prompt content")
	assert.Empty(t, findings)
}

func Test_Builtin_NoBidiControlCharacters_ReportsPreciseRuneDetailsInPathLikeToken(t *testing.T) {
	findings := evaluateRule(t, "open /tmp/\u2066secret.txt")
	require.Len(t, findings, 1)
	assert.Equal(t, "Bidirectional control character detected (LEFT-TO-RIGHT ISOLATE, isolate) inside URL/path-like token", findings[0].Message)
	assert.Equal(t, rules.Position{Line: 1, Column: 11}, findings[0].Position)
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
