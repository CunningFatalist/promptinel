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

	findings := New().CheckDocument(rules.Context{}, rules.DocumentView{Content: content})
	require.Len(t, findings, 1)
	assert.Equal(t, "Zero-width character detected", findings[0].Message)
	assert.Equal(t, 2, findings[0].Position.Line)
	assert.Equal(t, 5, findings[0].Position.Column)
}

func Test_NoZeroWidth_CheckDocument_DoesNotMatchSafeText(t *testing.T) {
	findings := New().CheckDocument(rules.Context{}, rules.DocumentView{Content: "plain text"})
	assert.Empty(t, findings)
}
