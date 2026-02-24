package nozerowidth

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoZeroWidth_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-zero-width", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoZeroWidth_CheckDocument_DetectsZeroWidthCharacters(t *testing.T) {
	content := "safe\nline\u200B hidden"

	findings := evaluateRule(t, content)
	require.Len(t, findings, 1)
	assert.Equal(t, "Zero-width character detected", findings[0].Message)
	assert.Equal(t, 2, findings[0].Position.Line)
	assert.Equal(t, 5, findings[0].Position.Column)
}

func Test_NoZeroWidth_CheckDocument_DoesNotMatchSafeText(t *testing.T) {
	findings := evaluateRule(t, "plain text")
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
