package scanfinding

const (
	// OversizedFileSkipID identifies findings for files skipped due to size limits.
	OversizedFileSkipID = "scan-file-too-large"
	// UnreadableFileSkipID identifies findings for files skipped due to read/metadata errors.
	UnreadableFileSkipID = "scan-file-unreadable"
)
