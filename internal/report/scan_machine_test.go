package report

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/finding"
	"github.com/CunningFatalist/promptinel/internal/ruledocs"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Report_WriteScanJSON_UsesStableSchemaAndOrdering(t *testing.T) {
	summary := scanMachineSummaryForTest()

	var output bytes.Buffer
	err := WriteScanJSON(&output, summary)
	require.NoError(t, err)

	var payload scanJSONReport
	require.NoError(t, unmarshalJSON(output.Bytes(), &payload))

	assert.Equal(t, scanJSONSchemaVersion, payload.SchemaVersion)
	assert.Equal(t, "promptinel_scan", payload.Format)
	require.Len(t, payload.Findings, 2)
	assert.Equal(t, "a.md", payload.Findings[0].Path)
	assert.Equal(t, "rule-a", payload.Findings[0].RuleID)
	assert.Equal(t, ruledocs.URL("RuleA.md"), payload.Findings[0].DocsURL)
	assert.Equal(t, []int{1, 2}, payload.Findings[0].Lines)
	assert.Equal(t, "z.md", payload.Findings[1].Path)
	require.Len(t, payload.OversizedSkip, 1)
	assert.Equal(t, "big.md", payload.OversizedSkip[0].Path)
	assert.Equal(t, 2, payload.Summary.Findings)
	assert.Equal(t, 1, payload.Summary.OversizedSkips)
	assert.Equal(t, 1, payload.Summary.FilteredBaseline)
	assert.Equal(t, "WARN", payload.Summary.Policy)
}

func Test_Report_WriteScanJSON_IsDeterministicForEquivalentInput(t *testing.T) {
	firstSummary := scanMachineSummaryForTest()
	secondSummary := scanMachineSummaryForTest()
	secondSummary.Findings = []finding.FileFinding{
		secondSummary.Findings[2],
		secondSummary.Findings[1],
		secondSummary.Findings[0],
	}

	var first bytes.Buffer
	var second bytes.Buffer
	require.NoError(t, WriteScanJSON(&first, firstSummary))
	require.NoError(t, WriteScanJSON(&second, secondSummary))
	assert.Equal(t, first.String(), second.String())
}

func Test_Report_WriteScanJSON_ParsesSummaryParityWithTextMode(t *testing.T) {
	summary := scanMachineSummaryForTest()

	var textOutput bytes.Buffer
	require.NoError(t, WriteScanText(&textOutput, summary))

	var jsonOutput bytes.Buffer
	require.NoError(t, WriteScanJSON(&jsonOutput, summary))
	var payload scanJSONReport
	require.NoError(t, unmarshalJSON(jsonOutput.Bytes(), &payload))

	assert.Contains(t, textOutput.String(), " - findings: 2")
	assert.Contains(t, textOutput.String(), " - oversized_skips: 1")
	assert.Equal(t, 2, payload.Summary.Findings)
	assert.Equal(t, 1, payload.Summary.OversizedSkips)
}

func Test_Report_WriteScanJSON_ReturnsErrorWhenWriterFails(t *testing.T) {
	err := WriteScanJSON(&failAfterNWriter{remainingWrites: 0}, scanMachineSummaryForTest())
	require.Error(t, err)
}

func Test_Report_WriteScanSARIF_UsesStableSchemaAndFindings(t *testing.T) {
	summary := scanMachineSummaryForTest()

	var output bytes.Buffer
	err := WriteScanSARIF(&output, summary)
	require.NoError(t, err)

	var payload sarifLog
	require.NoError(t, unmarshalJSON(output.Bytes(), &payload))

	assert.Equal(t, sarifVersion, payload.Version)
	assert.Equal(t, sarifSchemaURI, payload.Schema)
	require.Len(t, payload.Runs, 1)

	run := payload.Runs[0]
	require.Len(t, run.Results, 3)
	assert.Equal(t, "rule-a", run.Results[0].RuleID)
	require.Len(t, run.Results[0].Locations, 2)
	assert.Equal(t, "a.md", run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 1, run.Results[0].Locations[0].PhysicalLocation.Region.StartLine)
	assert.Equal(t, 2, run.Results[0].Locations[1].PhysicalLocation.Region.StartLine)
	assert.Equal(t, "finding", run.Results[0].Properties.Category)
	assert.Equal(t, "scan-file-too-large", run.Results[2].RuleID)
	assert.Equal(t, "oversized_skip", run.Results[2].Properties.Category)
	assert.Equal(t, "note", run.Results[2].Level)

	require.Len(t, run.Tool.Driver.Rules, 3)
	assert.Equal(t, "rule-a", run.Tool.Driver.Rules[0].ID)
	assert.Equal(t, ruledocs.URL("RuleA.md"), run.Tool.Driver.Rules[0].HelpURI)
	assert.Equal(t, "rule-z", run.Tool.Driver.Rules[1].ID)
	assert.Equal(t, ruledocs.URL("RuleZ.md"), run.Tool.Driver.Rules[1].HelpURI)
	assert.Equal(t, "scan-file-too-large", run.Tool.Driver.Rules[2].ID)

	require.Len(t, run.Invocations, 1)
	assert.Equal(t, scanSARIFSchemaVersion, run.Invocations[0].Properties.PromptinelSchemaVersion)
	assert.Equal(t, 2, run.Invocations[0].Properties.Findings)
	assert.Equal(t, 1, run.Invocations[0].Properties.OversizedSkips)
	assert.Equal(t, "WARN", run.Invocations[0].Properties.Policy)
}

func Test_Report_WriteScanSARIF_IsDeterministicForEquivalentInput(t *testing.T) {
	firstSummary := scanMachineSummaryForTest()
	secondSummary := scanMachineSummaryForTest()
	secondSummary.Findings = []finding.FileFinding{
		secondSummary.Findings[2],
		secondSummary.Findings[1],
		secondSummary.Findings[0],
	}

	var first bytes.Buffer
	var second bytes.Buffer
	require.NoError(t, WriteScanSARIF(&first, firstSummary))
	require.NoError(t, WriteScanSARIF(&second, secondSummary))
	assert.Equal(t, first.String(), second.String())
}

func Test_Report_WriteScanSARIF_EscapesRelativeArtifactURI(t *testing.T) {
	path := filepath.Join("dir with space", "a#b.md")
	summary := ScanSummary{
		Findings: []finding.FileFinding{
			{
				Path: path,
				Finding: rules.Finding{
					ID:       "rule-a",
					Severity: config.SeverityMedium,
					Message:  "a finding",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		PolicyOutcome: exitcode.CodeWarn,
	}

	var output bytes.Buffer
	require.NoError(t, WriteScanSARIF(&output, summary))

	var payload sarifLog
	require.NoError(t, unmarshalJSON(output.Bytes(), &payload))
	require.Len(t, payload.Runs, 1)
	require.Len(t, payload.Runs[0].Results, 1)

	artifactURI := payload.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	expectedURI := (&url.URL{Path: filepath.ToSlash(path)}).String()
	assert.Equal(t, expectedURI, artifactURI)
}

func Test_Report_WriteScanSARIF_UsesFileURIForAbsolutePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file with space.md")
	summary := ScanSummary{
		Findings: []finding.FileFinding{
			{
				Path: path,
				Finding: rules.Finding{
					ID:       "rule-a",
					Severity: config.SeverityMedium,
					Message:  "a finding",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		PolicyOutcome: exitcode.CodeWarn,
	}

	var output bytes.Buffer
	require.NoError(t, WriteScanSARIF(&output, summary))

	var payload sarifLog
	require.NoError(t, unmarshalJSON(output.Bytes(), &payload))
	require.Len(t, payload.Runs, 1)
	require.Len(t, payload.Runs[0].Results, 1)

	artifactURI := payload.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	expectedURI := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
	assert.Equal(t, expectedURI, artifactURI)
}

func Test_Report_WriteScanSARIF_ReturnsErrorWhenWriterFails(t *testing.T) {
	err := WriteScanSARIF(&failAfterNWriter{remainingWrites: 0}, scanMachineSummaryForTest())
	require.Error(t, err)
}

func Test_Report_RegisterSARIFDescriptor_UsesMostSevereLevel(t *testing.T) {
	descriptors := map[string]sarifReportingDescriptor{}

	registerSARIFDescriptor(descriptors, groupedFinding{
		id:       "rule-a",
		message:  "message",
		severity: config.SeverityLow,
		docsURL:  ruledocs.URL("RuleA.md"),
	})
	registerSARIFDescriptor(descriptors, groupedFinding{
		id:       "rule-a",
		message:  "message",
		severity: config.SeverityHigh,
		docsURL:  ruledocs.URL("RuleA.md"),
	})

	require.Len(t, descriptors, 1)
	assert.Equal(t, "error", descriptors["rule-a"].DefaultConfiguration.Level)
	assert.Equal(t, ruledocs.URL("RuleA.md"), descriptors["rule-a"].HelpURI)
}

func Test_Report_BuildSARIFLocationsAndLevelHelpers(t *testing.T) {
	locations := buildSARIFLocations("file.md", []int{0, -1})
	require.Len(t, locations, 1)
	assert.Equal(t, 1, locations[0].PhysicalLocation.Region.StartLine)
	assert.Equal(t, 1, locations[0].PhysicalLocation.Region.StartColumn)

	assert.Equal(t, "error", sarifLevelForSeverity(config.SeverityHigh))
	assert.Equal(t, "warning", sarifLevelForSeverity(config.SeverityMedium))
	assert.Equal(t, "note", sarifLevelForSeverity(config.SeverityLow))
	assert.Equal(t, 3, sarifLevelRank("error"))
	assert.Equal(t, 2, sarifLevelRank("warning"))
	assert.Equal(t, 1, sarifLevelRank("note"))
}

func scanMachineSummaryForTest() ScanSummary {
	return ScanSummary{
		Findings: []finding.FileFinding{
			{
				Path: "z.md",
				Finding: rules.Finding{
					ID:       "rule-z",
					Severity: config.SeverityHigh,
					Message:  "z finding",
					Position: rules.Position{Line: 9, Column: 1},
				},
			},
			{
				Path: "a.md",
				Finding: rules.Finding{
					ID:       "rule-a",
					Severity: config.SeverityMedium,
					Message:  "a finding",
					Position: rules.Position{Line: 2, Column: 1},
				},
			},
			{
				Path: "a.md",
				Finding: rules.Finding{
					ID:       "rule-a",
					Severity: config.SeverityMedium,
					Message:  "a finding",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		OversizedSkipped: []finding.FileFinding{
			{
				Path: "big.md",
				Finding: rules.Finding{
					ID:       finding.OversizedFileSkipID,
					Severity: config.SeverityLow,
					Message:  "File skipped: size 99 bytes exceeds limits.max_file_size_bytes (10)",
					Position: rules.Position{Line: 1, Column: 1},
				},
			},
		},
		Environment: config.Environment{
			CanExecuteShell:     true,
			CanAccessFilesystem: true,
			CanAccessNetwork:    true,
			HasSecrets:          false,
		},
		BaselineFiltered: 1,
		PolicyOutcome:    exitcode.CodeWarn,
		RuleDocs: map[string]string{
			"rule-a": ruledocs.URL("RuleA.md"),
			"rule-z": ruledocs.URL("RuleZ.md"),
		},
	}
}

func unmarshalJSON(payload []byte, target any) error {
	return json.Unmarshal(payload, target)
}
