package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
)

// ScanSummary contains rendered scan outcome data.
type ScanSummary struct {
	Findings         []engine.FileFinding
	Environment      config.Environment
	BaselineFiltered int
	PolicyOutcome    exitcode.Code
}

// WriteScanText writes a deterministic text report for scan findings.
func WriteScanText(w io.Writer, summary ScanSummary) error {
	groupedFindings := groupFindings(summary.Findings)

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
		}
	}

	if _, err := fmt.Fprintln(w, "\nSummary:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - findings: %d\n", len(groupedFindings)); err != nil {
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

type groupedFinding struct {
	path     string
	id       string
	severity config.Severity
	message  string
	lines    []int
}

func groupFindings(findings []engine.FileFinding) []groupedFinding {
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

func sanitizeForTerminal(value string) string {
	if value == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		switch {
		case r == '\n':
			builder.WriteString(`\n`)
		case r == '\r':
			builder.WriteString(`\r`)
		case r == '\t':
			builder.WriteString(`\t`)
		case isControlRune(r):
			builder.WriteString(`\x`)
			builder.WriteString(strconv.FormatInt(int64(r), 16))
		default:
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

func isControlRune(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	return unicode.IsControl(r)
}
