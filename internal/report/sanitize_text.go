package report

import (
	"fmt"
	"io"

	"github.com/CunningFatalist/promptinel/internal/sanitize"
)

// WriteSanitizeText writes deterministic sanitize command output.
func WriteSanitizeText(w io.Writer, result sanitize.Result) error {
	for _, event := range result.Events {
		switch event.Action {
		case sanitize.ActionSkipped:
			if _, err := fmt.Fprintf(w, "%s: skipped (%s)\n", sanitizeForTerminal(event.Path), sanitizeForTerminal(event.Reason)); err != nil {
				return err
			}
		case sanitize.ActionWouldSanitize:
			if _, err := fmt.Fprintf(
				w,
				"%s: would sanitize (line_endings=%d, zero_width=%d)\n",
				sanitizeForTerminal(event.Path),
				event.LineEndingsNormalized,
				event.ZeroWidthRunesStripped,
			); err != nil {
				return err
			}
		case sanitize.ActionSanitized:
			if _, err := fmt.Fprintf(
				w,
				"%s: sanitized (line_endings=%d, zero_width=%d)\n",
				sanitizeForTerminal(event.Path),
				event.LineEndingsNormalized,
				event.ZeroWidthRunesStripped,
			); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "Summary:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - files: %d\n", result.Summary.Files); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - changed: %d\n", result.Summary.Changed); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - skipped: %d\n", result.Summary.Skipped); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - line_endings: %d\n", result.Summary.LineEndingsNormalized); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, " - zero_width: %d\n", result.Summary.ZeroWidthRunesStripped); err != nil {
		return err
	}
	if result.Summary.Changed > 0 && !result.Summary.Applied {
		if _, err := fmt.Fprintln(w, "Re-run with --apply to persist changes."); err != nil {
			return err
		}
	}
	return nil
}
