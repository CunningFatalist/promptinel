package report

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/CunningFatalist/promptinel/internal/config"
)

const (
	scanSARIFSchemaVersion = "1.0.0"
	sarifVersion           = "2.1.0"
	sarifSchemaURI         = "https://json.schemastore.org/sarif-2.1.0.json"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifToolComponent `json:"driver"`
}

type sarifToolComponent struct {
	Name           string                     `json:"name"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules,omitempty"`
}

type sarifReportingDescriptor struct {
	ID                   string                      `json:"id"`
	Name                 string                      `json:"name"`
	ShortDescription     sarifMessage                `json:"shortDescription"`
	DefaultConfiguration sarifReportingConfiguration `json:"defaultConfiguration"`
}

type sarifReportingConfiguration struct {
	Level string `json:"level"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                      `json:"executionSuccessful"`
	Properties          sarifInvocationProperties `json:"properties"`
}

type sarifInvocationProperties struct {
	PromptinelSchemaVersion string `json:"promptinel_schema_version"`
	Policy                  string `json:"policy"`
	Findings                int    `json:"findings"`
	OversizedSkips          int    `json:"oversized_skips"`
	FilteredByBaseline      int    `json:"filtered_by_baseline,omitempty"`
}

type sarifResult struct {
	RuleID     string                `json:"ruleId"`
	Level      string                `json:"level"`
	Message    sarifMessage          `json:"message"`
	Locations  []sarifLocation       `json:"locations"`
	Properties sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	Severity config.Severity `json:"severity"`
	Category string          `json:"category"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// WriteScanSARIF writes a deterministic SARIF 2.1.0 report for scan findings.
func WriteScanSARIF(w io.Writer, summary ScanSummary) error {
	groupedFindings := orderedGroupedFindings(summary.Findings)
	groupedOversizedSkipped := orderedGroupedFindings(summary.OversizedSkipped)

	descriptorsByID := make(map[string]sarifReportingDescriptor, len(groupedFindings)+len(groupedOversizedSkipped))
	results := make([]sarifResult, 0, len(groupedFindings)+len(groupedOversizedSkipped))
	addResult := func(grouped groupedFinding, category string) {
		registerSARIFDescriptor(descriptorsByID, grouped)
		results = append(results, buildSARIFResult(grouped, category))
	}

	for _, grouped := range groupedFindings {
		addResult(grouped, "finding")
	}
	for _, grouped := range groupedOversizedSkipped {
		addResult(grouped, "oversized_skip")
	}

	descriptorIDs := make([]string, 0, len(descriptorsByID))
	for id := range descriptorsByID {
		descriptorIDs = append(descriptorIDs, id)
	}
	sort.Strings(descriptorIDs)

	descriptors := make([]sarifReportingDescriptor, 0, len(descriptorIDs))
	for _, id := range descriptorIDs {
		descriptors = append(descriptors, descriptorsByID[id])
	}

	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchemaURI,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifToolComponent{
					Name:           "promptinel",
					InformationURI: "https://github.com/CunningFatalist/promptinel",
					Rules:          descriptors,
				},
			},
			Results: results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				Properties: sarifInvocationProperties{
					PromptinelSchemaVersion: scanSARIFSchemaVersion,
					Policy:                  outcomeLabel(summary.PolicyOutcome),
					Findings:                len(groupedFindings),
					OversizedSkips:          len(groupedOversizedSkipped),
					FilteredByBaseline:      summary.BaselineFiltered,
				},
			}},
		}},
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func registerSARIFDescriptor(descriptorsByID map[string]sarifReportingDescriptor, grouped groupedFinding) {
	level := sarifLevelForSeverity(grouped.severity)
	descriptor, exists := descriptorsByID[grouped.id]
	if !exists {
		descriptorsByID[grouped.id] = sarifReportingDescriptor{
			ID:               grouped.id,
			Name:             grouped.id,
			ShortDescription: sarifMessage{Text: grouped.message},
			DefaultConfiguration: sarifReportingConfiguration{
				Level: level,
			},
		}
		return
	}

	if sarifLevelRank(level) > sarifLevelRank(descriptor.DefaultConfiguration.Level) {
		descriptor.DefaultConfiguration.Level = level
		descriptorsByID[grouped.id] = descriptor
	}
}

func buildSARIFResult(grouped groupedFinding, category string) sarifResult {
	artifactURI := buildSARIFArtifactURI(grouped.path)

	return sarifResult{
		RuleID: grouped.id,
		Level:  sarifLevelForSeverity(grouped.severity),
		Message: sarifMessage{
			Text: grouped.message,
		},
		Locations: buildSARIFLocations(artifactURI, grouped.lines),
		Properties: sarifResultProperties{
			Severity: grouped.severity,
			Category: category,
		},
	}
}

func buildSARIFArtifactURI(path string) string {
	normalizedPath := filepath.ToSlash(path)
	if filepath.IsAbs(path) {
		return (&url.URL{Scheme: "file", Path: normalizedPath}).String()
	}
	return (&url.URL{Path: normalizedPath}).String()
}

func buildSARIFLocations(artifactURI string, lines []int) []sarifLocation {
	validLines := make([]int, 0, len(lines))
	for _, line := range lines {
		if line > 0 {
			validLines = append(validLines, line)
		}
	}
	if len(validLines) == 0 {
		validLines = append(validLines, 1)
	}

	locations := make([]sarifLocation, 0, len(validLines))
	for _, line := range validLines {
		locations = append(locations, sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI: artifactURI,
				},
				Region: sarifRegion{
					StartLine:   line,
					StartColumn: 1,
				},
			},
		})
	}
	return locations
}

func sarifLevelForSeverity(severity config.Severity) string {
	switch severity {
	case config.SeverityHigh:
		return "error"
	case config.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifLevelRank(level string) int {
	switch level {
	case "error":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}
