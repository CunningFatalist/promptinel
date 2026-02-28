package report

import (
	"fmt"
	"io"
)

// BaselineSummary contains rendered baseline outcome data.
type BaselineSummary struct {
	File            string
	Entries         int
	Updated         bool
	PreviousEntries int
}

// WriteBaselineText writes deterministic baseline command output.
func WriteBaselineText(w io.Writer, summary BaselineSummary) error {
	if summary.Updated {
		delta := summary.Entries - summary.PreviousEntries
		_, err := fmt.Fprintf(
			w,
			"Updated baseline %s with %d entries (%+d compared to previous snapshot).\n",
			summary.File,
			summary.Entries,
			delta,
		)
		return err
	}

	_, err := fmt.Fprintf(w, "Created baseline %s with %d entries.\n", summary.File, summary.Entries)
	return err
}
