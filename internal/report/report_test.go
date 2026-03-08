package report

import (
	"bytes"
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/finding"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/sanitize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failAfterNWriter struct {
	remainingWrites int
}

func (w *failAfterNWriter) Write(p []byte) (int, error) {
	if w.remainingWrites == 0 {
		return 0, errors.New("forced write failure")
	}
	w.remainingWrites--
	return len(p), nil
}

func Test_Report_WriteScanText_GroupsFindingsByFileAndIncludesSummary(t *testing.T) {
	var output bytes.Buffer

	findings := []finding.FileFinding{
		{
			Path: "a.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityHigh,
				Message:  "message a",
				Position: rules.Position{Line: 2, Column: 4},
			},
		},
		{
			Path: "b.md",
			Finding: rules.Finding{
				ID:       "rule-b",
				Severity: config.SeverityLow,
				Message:  "message b",
				Position: rules.Position{Line: 1, Column: 1},
			},
		},
	}

	err := WriteScanText(&output, ScanSummary{
		Findings: findings,
		Environment: config.Environment{
			CanExecuteShell:     true,
			CanAccessFilesystem: true,
			CanAccessNetwork:    false,
			HasSecrets:          false,
		},
		BaselineFiltered: 1,
		PolicyOutcome:    exitcode.CodeFail,
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "Capabilities:")
	assert.Contains(t, rendered, "File: a.md")
	assert.Contains(t, rendered, "File: b.md")
	assert.Contains(t, rendered, "lines 2 [high] rule-a: message a")
	assert.Contains(t, rendered, "lines 1 [low] rule-b: message b")
	assert.Contains(t, rendered, "- findings: 2")
	assert.Contains(t, rendered, "- oversized_skips: 0")
	assert.Contains(t, rendered, "- filtered_by_baseline: 1")
	assert.Contains(t, rendered, "- policy: FAIL")
}

func Test_Report_WriteScanText_DeduplicatesRulePerFileAndShowsAllLines(t *testing.T) {
	var output bytes.Buffer

	findings := []finding.FileFinding{
		{
			Path: "dup.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityMedium,
				Message:  "duplicate",
				Position: rules.Position{Line: 1, Column: 4},
			},
		},
		{
			Path: "dup.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityMedium,
				Message:  "duplicate",
				Position: rules.Position{Line: 5, Column: 2},
			},
		},
		{
			Path: "dup.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityMedium,
				Message:  "duplicate",
				Position: rules.Position{Line: 4, Column: 8},
			},
		},
		{
			Path: "dup.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityMedium,
				Message:  "duplicate",
				Position: rules.Position{Line: 18, Column: 1},
			},
		},
	}

	err := WriteScanText(&output, ScanSummary{
		Findings:      findings,
		Environment:   config.Environment{},
		PolicyOutcome: exitcode.CodeWarn,
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "File: dup.md")
	assert.Contains(t, rendered, "lines 1, 4, 5, and 18 [medium] rule-a: duplicate")
	assert.Contains(t, rendered, "- findings: 1")
	assert.Contains(t, rendered, "- oversized_skips: 0")
	assert.Contains(t, rendered, "- policy: WARN")
}

func Test_Report_WriteScanText_PrintsNoneWhenNoFindings(t *testing.T) {
	var output bytes.Buffer

	err := WriteScanText(&output, ScanSummary{
		Environment:   config.Environment{},
		PolicyOutcome: exitcode.CodePass,
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "Findings: none")
	assert.Contains(t, rendered, "Oversized Skips: none")
	assert.Contains(t, rendered, "- oversized_skips: 0")
	assert.Contains(t, rendered, "- policy: PASS")
}

func Test_Report_WriteScanText_EscapesControlCharacters(t *testing.T) {
	var output bytes.Buffer

	err := WriteScanText(&output, ScanSummary{
		Findings: []finding.FileFinding{
			{
				Path: "bad\npath.md",
				Finding: rules.Finding{
					ID:       "rule\tname",
					Severity: config.SeverityMedium,
					Message:  "hello\rworld",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		Environment:   config.Environment{},
		PolicyOutcome: exitcode.CodeWarn,
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "File: bad\\npath.md")
	assert.Contains(t, rendered, "rule\\tname: hello\\rworld")
	assert.Contains(t, rendered, "- oversized_skips: 0")
}

func Test_Report_WriteScanText_IncludesOversizedSkipsIndependentlyFromFindings(t *testing.T) {
	var output bytes.Buffer

	err := WriteScanText(&output, ScanSummary{
		OversizedSkipped: []finding.FileFinding{
			{
				Path: "huge.md",
				Finding: rules.Finding{
					ID:       "scan-file-too-large",
					Severity: config.SeverityLow,
					Message:  "File skipped: size 99 bytes exceeds limits.max_file_size_bytes (10)",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		Environment:   config.Environment{},
		PolicyOutcome: exitcode.CodePass,
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "Findings: none")
	assert.Contains(t, rendered, "Oversized Skips:")
	assert.Contains(t, rendered, "huge.md [low] scan-file-too-large")
	assert.Contains(t, rendered, "- oversized_skips: 1")
	assert.Contains(t, rendered, "- policy: PASS")
}

func Test_Report_WriteScanText_ReturnsErrorAcrossWritePoints_WithFindingsAndOversizedSkips(t *testing.T) {
	summary := ScanSummary{
		Findings: []finding.FileFinding{
			{
				Path: "a.md",
				Finding: rules.Finding{
					ID:       "rule-a",
					Severity: config.SeverityHigh,
					Message:  "message a",
					Position: rules.Position{Line: 2, Column: 4},
				},
			},
		},
		OversizedSkipped: []finding.FileFinding{
			{
				Path: "huge.md",
				Finding: rules.Finding{
					ID:       "scan-file-too-large",
					Severity: config.SeverityLow,
					Message:  "File skipped: size 99 bytes exceeds limits.max_file_size_bytes (10)",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		Environment:      config.Environment{},
		BaselineFiltered: 1,
		PolicyOutcome:    exitcode.CodeFail,
	}

	for failAt := 0; failAt <= 13; failAt++ {
		err := WriteScanText(&failAfterNWriter{remainingWrites: failAt}, summary)
		require.Error(t, err)
	}
}

func Test_Report_WriteScanText_ReturnsErrorAcrossWritePoints_WithNoFindingsNoOversizedSkips(t *testing.T) {
	summary := ScanSummary{
		Environment:   config.Environment{},
		PolicyOutcome: exitcode.CodePass,
	}

	for failAt := 0; failAt <= 9; failAt++ {
		err := WriteScanText(&failAfterNWriter{remainingWrites: failAt}, summary)
		require.Error(t, err)
	}
}

func Test_Report_WriteBaselineText_CreateAndUpdate(t *testing.T) {
	var created bytes.Buffer
	err := WriteBaselineText(&created, BaselineSummary{
		File:    ".promptinel-baseline.json",
		Entries: 7,
	})
	require.NoError(t, err)
	assert.Equal(t, "Created baseline .promptinel-baseline.json with 7 entries.\n", created.String())

	var updated bytes.Buffer
	err = WriteBaselineText(&updated, BaselineSummary{
		File:            ".promptinel-baseline.json",
		Entries:         9,
		Updated:         true,
		PreviousEntries: 12,
	})
	require.NoError(t, err)
	assert.Equal(t, "Updated baseline .promptinel-baseline.json with 9 entries (-3 compared to previous snapshot).\n", updated.String())
}

func Test_Report_SanitizeForTerminal(t *testing.T) {
	assert.Equal(t, "", sanitizeForTerminal(""))
	assert.Equal(t, "hello\\nworld\\r\\t\\x1", sanitizeForTerminal("hello\nworld\r\t\x01"))
	assert.Equal(t, string(utf8.RuneError), sanitizeForTerminal(string(utf8.RuneError)))
}

func Test_Report_IsControlRune(t *testing.T) {
	assert.True(t, isControlRune('\x01'))
	assert.False(t, isControlRune('a'))
	assert.False(t, isControlRune(utf8.RuneError))
}

func Test_Report_WriteBaselineText_EscapesControlCharacters(t *testing.T) {
	var output bytes.Buffer
	err := WriteBaselineText(&output, BaselineSummary{
		File:    "bad\nfile\tname.json",
		Entries: 1,
	})
	require.NoError(t, err)
	assert.Contains(t, output.String(), "bad\\nfile\\tname.json")
}

func Test_Report_WriteSanitizeText_WritesEventsAndSummary(t *testing.T) {
	var output bytes.Buffer

	err := WriteSanitizeText(&output, sanitize.Result{
		Events: []sanitize.Event{
			{Path: "a.md", Action: sanitize.ActionWouldSanitize, LineEndingsNormalized: 1, ZeroWidthRunesStripped: 2},
			{Path: "b.md", Action: sanitize.ActionSkipped, Reason: "non-regular file"},
		},
		Summary: sanitize.Summary{
			Files:                  2,
			Changed:                1,
			Skipped:                1,
			LineEndingsNormalized:  1,
			ZeroWidthRunesStripped: 2,
			Applied:                false,
		},
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "a.md: would sanitize (line_endings=1, zero_width=2)")
	assert.Contains(t, rendered, "b.md: skipped (non-regular file)")
	assert.Contains(t, rendered, "Summary:")
	assert.Contains(t, rendered, " - files: 2")
	assert.Contains(t, rendered, " - changed: 1")
	assert.Contains(t, rendered, " - skipped: 1")
	assert.Contains(t, rendered, " - line_endings: 1")
	assert.Contains(t, rendered, " - zero_width: 2")
	assert.Contains(t, rendered, "Re-run with --apply to persist changes.")
}

func Test_Report_WriteSanitizeText_EscapesControlCharacters(t *testing.T) {
	var output bytes.Buffer
	err := WriteSanitizeText(&output, sanitize.Result{
		Events: []sanitize.Event{
			{
				Path:   "a\nb.md",
				Action: sanitize.ActionSkipped,
				Reason: "bad\treason\rhere",
			},
		},
		Summary: sanitize.Summary{
			Files:   1,
			Skipped: 1,
		},
	})
	require.NoError(t, err)

	rendered := output.String()
	assert.Contains(t, rendered, "a\\nb.md: skipped (bad\\treason\\rhere)")
}
