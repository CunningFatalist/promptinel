package report

import (
	"bytes"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Report_WriteScanText_GroupsFindingsByFileAndIncludesSummary(t *testing.T) {
	var output bytes.Buffer

	findings := []engine.FileFinding{
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
	assert.Contains(t, rendered, "- filtered_by_baseline: 1")
	assert.Contains(t, rendered, "- policy: FAIL")
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
	assert.Contains(t, rendered, "- policy: PASS")
}
