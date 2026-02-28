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
			if _, err := fmt.Fprintf(w, "%s: skipped (%s)\n", event.Path, event.Reason); err != nil {
				return err
			}
		case sanitize.ActionWouldSanitize:
			if _, err := fmt.Fprintf(
				w,
				"%s: would sanitize (line_endings=%d, zero_width=%d)\n",
				event.Path,
				event.LineEndingsNormalized,
				event.ZeroWidthRunesStripped,
			); err != nil {
				return err
			}
		case sanitize.ActionSanitized:
			if _, err := fmt.Fprintf(
				w,
				"%s: sanitized (line_endings=%d, zero_width=%d)\n",
				event.Path,
				event.LineEndingsNormalized,
				event.ZeroWidthRunesStripped,
			); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(
		w,
		"\nSummary: files=%d changed=%d skipped=%d line_endings=%d zero_width=%d\n",
		result.Summary.Files,
		result.Summary.Changed,
		result.Summary.Skipped,
		result.Summary.LineEndingsNormalized,
		result.Summary.ZeroWidthRunesStripped,
	); err != nil {
		return err
	}
	if result.Summary.Changed > 0 && !result.Summary.Applied {
		if _, err := fmt.Fprintln(w, "Re-run with --apply to persist changes."); err != nil {
			return err
		}
	}
	return nil
}
