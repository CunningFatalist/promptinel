package report

import (
	"encoding/json"
	"io"

	"github.com/CunningFatalist/promptinel/internal/config"
)

const scanJSONSchemaVersion = "1.0.0"

type scanJSONReport struct {
	SchemaVersion string               `json:"schema_version"`
	Format        string               `json:"format"`
	Capabilities  scanJSONCapabilities `json:"capabilities"`
	Findings      []scanJSONFinding    `json:"findings"`
	OversizedSkip []scanJSONFinding    `json:"oversized_skips"`
	Summary       scanJSONSummary      `json:"summary"`
}

type scanJSONCapabilities struct {
	CanExecuteShell     bool `json:"can_execute_shell"`
	CanAccessFilesystem bool `json:"can_access_filesystem"`
	CanAccessNetwork    bool `json:"can_access_network"`
	HasSecrets          bool `json:"has_secrets"`
}

type scanJSONFinding struct {
	Path     string          `json:"path"`
	RuleID   string          `json:"rule_id"`
	Severity config.Severity `json:"severity"`
	Message  string          `json:"message"`
	DocsURL  string          `json:"docs_url,omitempty"`
	Lines    []int           `json:"lines,omitempty"`
}

type scanJSONSummary struct {
	Findings         int    `json:"findings"`
	OversizedSkips   int    `json:"oversized_skips"`
	FilteredBaseline int    `json:"filtered_by_baseline,omitempty"`
	Policy           string `json:"policy"`
}

// WriteScanJSON writes a deterministic JSON report for scan findings.
func WriteScanJSON(w io.Writer, summary ScanSummary) error {
	groupedFindings := orderedGroupedFindings(summary.Findings, summary.RuleDocs)
	groupedOversizedSkipped := orderedGroupedFindings(summary.OversizedSkipped, summary.RuleDocs)

	report := scanJSONReport{
		SchemaVersion: scanJSONSchemaVersion,
		Format:        "promptinel_scan",
		Capabilities: scanJSONCapabilities{
			CanExecuteShell:     summary.Environment.CanExecuteShell,
			CanAccessFilesystem: summary.Environment.CanAccessFilesystem,
			CanAccessNetwork:    summary.Environment.CanAccessNetwork,
			HasSecrets:          summary.Environment.HasSecrets,
		},
		Findings:      make([]scanJSONFinding, 0, len(groupedFindings)),
		OversizedSkip: make([]scanJSONFinding, 0, len(groupedOversizedSkipped)),
		Summary: scanJSONSummary{
			Findings:       len(groupedFindings),
			OversizedSkips: len(groupedOversizedSkipped),
			Policy:         outcomeLabel(summary.PolicyOutcome),
		},
	}
	if summary.BaselineFiltered > 0 {
		report.Summary.FilteredBaseline = summary.BaselineFiltered
	}

	for _, finding := range groupedFindings {
		report.Findings = append(report.Findings, scanJSONFinding{
			Path:     finding.path,
			RuleID:   finding.id,
			Severity: finding.severity,
			Message:  finding.message,
			DocsURL:  finding.docsURL,
			Lines:    cloneIntSlice(finding.lines),
		})
	}

	for _, skipped := range groupedOversizedSkipped {
		report.OversizedSkip = append(report.OversizedSkip, scanJSONFinding{
			Path:     skipped.path,
			RuleID:   skipped.id,
			Severity: skipped.severity,
			Message:  skipped.message,
			DocsURL:  skipped.docsURL,
			Lines:    cloneIntSlice(skipped.lines),
		})
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func cloneIntSlice(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]int, len(values))
	copy(cloned, values)
	return cloned
}
