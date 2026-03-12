package finding

import (
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/scanfinding"
)

const (
	// OversizedFileSkipID identifies findings for files skipped due to size limits.
	OversizedFileSkipID = scanfinding.OversizedFileSkipID
	// UnreadableFileSkipID identifies findings for files skipped due to read/metadata errors.
	UnreadableFileSkipID = scanfinding.UnreadableFileSkipID
)

// FileFinding links a finding to its source file path.
type FileFinding struct {
	Path string
	rules.Finding
}

// IsOversizedFileSkip reports whether finding indicates a size-limit skip.
func IsOversizedFileSkip(f FileFinding) bool {
	return f.ID == OversizedFileSkipID
}
