package finding

import "github.com/CunningFatalist/promptinel/internal/rules"

const (
	// OversizedFileSkipID identifies findings for files skipped due to size limits.
	OversizedFileSkipID = "scan-file-too-large"
	// UnreadableFileSkipID identifies findings for files skipped due to read/metadata errors.
	UnreadableFileSkipID = "scan-file-unreadable"
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
