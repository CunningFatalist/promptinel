package report

import (
	"bytes"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/sanitize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Report_WriteSanitizeText_RendersActionsAndSummary(t *testing.T) {
	var output bytes.Buffer

	err := WriteSanitizeText(&output, sanitize.Result{
		Events: []sanitize.Event{
			{Path: "skip\n.md", Action: sanitize.ActionSkipped, Reason: "because\tno"},
			{Path: "would.md", Action: sanitize.ActionWouldSanitize, LineEndingsNormalized: 2, ZeroWidthRunesStripped: 1},
			{Path: "done.md", Action: sanitize.ActionSanitized, LineEndingsNormalized: 1, ZeroWidthRunesStripped: 3},
		},
		Summary: sanitize.Summary{
			Files:                  3,
			Changed:                2,
			Skipped:                1,
			LineEndingsNormalized:  3,
			ZeroWidthRunesStripped: 4,
		},
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "skip\\n.md: skipped (because\\tno)")
	assert.Contains(t, rendered, "would.md: would sanitize (line_endings=2, zero_width=1)")
	assert.Contains(t, rendered, "done.md: sanitized (line_endings=1, zero_width=3)")
	assert.Contains(t, rendered, " - files: 3")
	assert.Contains(t, rendered, " - changed: 2")
	assert.Contains(t, rendered, " - skipped: 1")
	assert.Contains(t, rendered, "Re-run with --apply to persist changes.")
}

func Test_Report_WriteSanitizeText_OmitsRerunHintWhenApplied(t *testing.T) {
	var output bytes.Buffer

	err := WriteSanitizeText(&output, sanitize.Result{
		Summary: sanitize.Summary{
			Files:   1,
			Changed: 1,
			Applied: true,
		},
	})
	require.NoError(t, err)
	assert.NotContains(t, output.String(), "Re-run with --apply")
}

func Test_Report_WriteSanitizeText_ReturnsErrorWhenWriterFails(t *testing.T) {
	result := sanitize.Result{
		Events: []sanitize.Event{
			{Path: "a.md", Action: sanitize.ActionSkipped, Reason: "skip"},
			{Path: "b.md", Action: sanitize.ActionWouldSanitize, LineEndingsNormalized: 1, ZeroWidthRunesStripped: 2},
			{Path: "c.md", Action: sanitize.ActionSanitized, LineEndingsNormalized: 3, ZeroWidthRunesStripped: 4},
		},
		Summary: sanitize.Summary{
			Files:                  3,
			Changed:                2,
			Skipped:                1,
			LineEndingsNormalized:  4,
			ZeroWidthRunesStripped: 6,
		},
	}

	for failAt := 0; failAt <= 8; failAt++ {
		err := WriteSanitizeText(&failAfterNWriter{remainingWrites: failAt}, result)
		require.Error(t, err)
	}
}
