package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/finding"
)

// ScanSummary contains rendered scan outcome data.
type ScanSummary struct {
	Findings         []finding.FileFinding
	OversizedSkipped []finding.FileFinding
	Environment      config.Environment
	BaselineFiltered int
	PolicyOutcome    exitcode.Code
	RuleDocs         map[string]string
}

// WriteScanText writes a deterministic text report for scan findings.
func WriteScanText(w io.Writer, summary ScanSummary) error {
	groupedFindings := orderedGroupedFindings(summary.Findings, summary.RuleDocs)
	groupedOversizedSkipped := orderedGroupedFindings(summary.OversizedSkipped, summary.RuleDocs)

	if _, err := fmt.Fprintln(w, "Capabilities:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - can_execute_shell: %t\n", summary.Environment.CanExecuteShell); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - can_access_filesystem: %t\n", summary.Environment.CanAccessFilesystem); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - can_access_network: %t\n", summary.Environment.CanAccessNetwork); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - has_secrets: %t\n", summary.Environment.HasSecrets); err != nil {
		return err
	}

	if len(groupedFindings) == 0 {
		if _, err := fmt.Fprintln(w, "\nFindings: none"); err != nil {
			return err
		}
	} else {
		currentPath := ""
		for _, finding := range groupedFindings {
			if finding.path != currentPath {
				currentPath = finding.path
				if _, err := fmt.Fprintf(w, "\nFile: %s\n", sanitizeForTerminal(currentPath)); err != nil {
					return err
				}
			}

			lineSummary := summarizeLines(finding.lines)
			if _, err := fmt.Fprintf(
				w,
				" - lines %s [%s] %s: %s\n",
				lineSummary,
				finding.severity,
				sanitizeForTerminal(finding.id),
				sanitizeForTerminal(finding.message),
			); err != nil {
				return err
			}
			if finding.docsURL != "" {
				if _, err := fmt.Fprintf(w, "   docs: %s\n", sanitizeForTerminal(finding.docsURL)); err != nil {
					return err
				}
			}
		}
	}

	if len(groupedOversizedSkipped) == 0 {
		if _, err := fmt.Fprintln(w, "\nOversized Skips: none"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "\nOversized Skips:"); err != nil {
			return err
		}

		for _, skipped := range groupedOversizedSkipped {
			if _, err := fmt.Fprintf(
				w,
				" - %s [%s] %s: %s\n",
				sanitizeForTerminal(skipped.path),
				skipped.severity,
				sanitizeForTerminal(skipped.id),
				sanitizeForTerminal(skipped.message),
			); err != nil {
				return err
			}
			if skipped.docsURL != "" {
				if _, err := fmt.Fprintf(w, "   docs: %s\n", sanitizeForTerminal(skipped.docsURL)); err != nil {
					return err
				}
			}
		}
	}

	if _, err := fmt.Fprintln(w, "\nSummary:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - findings: %d\n", len(groupedFindings)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - oversized_skips: %d\n", len(groupedOversizedSkipped)); err != nil {
		return err
	}
	if summary.BaselineFiltered > 0 {
		if _, err := fmt.Fprintf(w, " - filtered_by_baseline: %d\n", summary.BaselineFiltered); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, " - policy: %s\n", outcomeLabel(summary.PolicyOutcome)); err != nil {
		return err
	}

	return nil
}

func orderedGroupedFindings(findings []finding.FileFinding, ruleDocs map[string]string) []groupedFinding {
	grouped := groupFindings(findings, ruleDocs)
	sort.SliceStable(grouped, func(i, j int) bool {
		if grouped[i].path != grouped[j].path {
			return grouped[i].path < grouped[j].path
		}
		if grouped[i].id != grouped[j].id {
			return grouped[i].id < grouped[j].id
		}
		if grouped[i].severity != grouped[j].severity {
			return grouped[i].severity < grouped[j].severity
		}
		return grouped[i].message < grouped[j].message
	})
	return grouped
}

type groupedFinding struct {
	path     string
	id       string
	severity config.Severity
	message  string
	lines    []int
	docsURL  string
}

func groupFindings(findings []finding.FileFinding, ruleDocs map[string]string) []groupedFinding {
	groupedByKey := make(map[string]*groupedFinding, len(findings))
	order := make([]string, 0, len(findings))

	for _, finding := range findings {
		key := finding.Path + "\n" + finding.ID
		grouped, exists := groupedByKey[key]
		if !exists {
			grouped = &groupedFinding{
				path:     finding.Path,
				id:       finding.ID,
				severity: finding.Severity,
				message:  finding.Message,
				lines:    make([]int, 0, 1),
				docsURL:  ruleDocs[finding.ID],
			}
			groupedByKey[key] = grouped
			order = append(order, key)
		}
		if finding.Position.Line > 0 {
			grouped.lines = append(grouped.lines, finding.Position.Line)
		}
	}

	groupedFindings := make([]groupedFinding, 0, len(order))
	for _, key := range order {
		grouped := groupedByKey[key]
		grouped.lines = uniqueSortedInts(grouped.lines)
		groupedFindings = append(groupedFindings, *grouped)
	}

	return groupedFindings
}

func uniqueSortedInts(values []int) []int {
	if len(values) <= 1 {
		return values
	}

	sorted := make([]int, len(values))
	copy(sorted, values)
	sort.Ints(sorted)

	unique := sorted[:1]
	for i := 1; i < len(sorted); i++ {
		if sorted[i] != sorted[i-1] {
			unique = append(unique, sorted[i])
		}
	}
	return unique
}

func summarizeLines(lines []int) string {
	if len(lines) == 0 {
		return "unknown"
	}
	if len(lines) == 1 {
		return strconv.Itoa(lines[0])
	}
	if len(lines) == 2 {
		return strconv.Itoa(lines[0]) + " and " + strconv.Itoa(lines[1])
	}

	lineStrings := make([]string, 0, len(lines))
	for _, line := range lines {
		lineStrings = append(lineStrings, strconv.Itoa(line))
	}
	return strings.Join(lineStrings[:len(lineStrings)-1], ", ") + ", and " + lineStrings[len(lineStrings)-1]
}

func outcomeLabel(code exitcode.Code) string {
	switch code {
	case exitcode.CodeFail:
		return "FAIL"
	case exitcode.CodeWarn:
		return "WARN"
	default:
		return "PASS"
	}
}
