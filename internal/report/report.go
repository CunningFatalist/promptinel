package report

import (
	"fmt"
	"io"

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

	if len(summary.Findings) == 0 {
		if _, err := fmt.Fprintln(w, "\nFindings: none"); err != nil {
			return err
		}
	} else {
		currentPath := ""
		for _, finding := range summary.Findings {
			if finding.Path != currentPath {
				currentPath = finding.Path
				if _, err := fmt.Fprintf(w, "\nFile: %s\n", currentPath); err != nil {
					return err
				}
			}

			if _, err := fmt.Fprintf(
				w,
				" - %d:%d [%s] %s: %s\n",
				finding.Position.Line,
				finding.Position.Column,
				finding.Severity,
				finding.ID,
				finding.Message,
			); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "\nSummary:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - findings: %d\n", len(summary.Findings)); err != nil {
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
