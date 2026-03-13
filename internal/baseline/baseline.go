package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/finding"
	"github.com/CunningFatalist/promptinel/internal/safefile"
)

const (
	// DefaultFileName is the default baseline snapshot file path.
	DefaultFileName = ".promptinel-baseline.json"
	// SnapshotVersion is the current baseline file format version.
	SnapshotVersion = 2
	// LegacySnapshotVersion is the previous baseline file format version.
	LegacySnapshotVersion = 1
)

var writeFileAtomically = safefile.WriteFileAtomically

// Snapshot stores accepted findings in a deterministic representation.
type Snapshot struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Entry represents one accepted finding.
type Entry struct {
	Hash     string          `json:"hash"`
	Path     string          `json:"path"`
	RuleID   string          `json:"rule_id"`
	Severity config.Severity `json:"severity"`
	Message  string          `json:"message"`
	Line     int             `json:"line"`
	Column   int             `json:"column"`
	Count    int             `json:"count,omitempty"`
}

// BuildSnapshot converts findings into a deterministic baseline snapshot.
func BuildSnapshot(findings []finding.FileFinding) Snapshot {
	entriesByHash := make(map[string]Entry, len(findings))
	for _, finding := range findings {
		hash := HashFinding(finding)
		entry, exists := entriesByHash[hash]
		if !exists {
			entriesByHash[hash] = Entry{
				Hash:     hash,
				Path:     finding.Path,
				RuleID:   finding.ID,
				Severity: finding.Severity,
				Message:  finding.Message,
				Line:     finding.Position.Line,
				Column:   finding.Position.Column,
				Count:    1,
			}
			continue
		}
		entry.Count++
		if entry.Line == 0 || positionComesBefore(finding.Position.Line, finding.Position.Column, entry.Line, entry.Column) {
			entry.Line = finding.Position.Line
			entry.Column = finding.Position.Column
		}
		entriesByHash[hash] = entry
	}

	entries := make([]Entry, 0, len(entriesByHash))
	for _, entry := range entriesByHash {
		entries = append(entries, entry)
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Hash < entries[j].Hash
	})

	return Snapshot{
		Version: SnapshotVersion,
		Entries: entries,
	}
}

// HashFinding returns a deterministic hash for one finding.
func HashFinding(finding finding.FileFinding) string {
	payload := strings.Join([]string{
		finding.Path,
		finding.ID,
		finding.Severity.String(),
		finding.Message,
	}, "\n")

	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func legacyHashFinding(f finding.FileFinding) string {
	payload := strings.Join([]string{
		f.Path,
		f.ID,
		f.Severity.String(),
		f.Message,
		fmt.Sprintf("%d", f.Position.Line),
		fmt.Sprintf("%d", f.Position.Column),
	}, "\n")

	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// FilterFindings removes findings already accepted by the provided snapshot.
func FilterFindings(findings []finding.FileFinding, snapshot Snapshot) []finding.FileFinding {
	if len(snapshot.Entries) == 0 {
		return findings
	}

	if snapshot.Version == LegacySnapshotVersion {
		accepted := make(map[string]struct{}, len(snapshot.Entries))
		for _, entry := range snapshot.Entries {
			accepted[entry.Hash] = struct{}{}
		}

		filtered := make([]finding.FileFinding, 0, len(findings))
		for _, finding := range findings {
			if _, ok := accepted[legacyHashFinding(finding)]; ok {
				continue
			}
			filtered = append(filtered, finding)
		}

		return filtered
	}

	acceptedCounts := make(map[string]int, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		count := entry.Count
		if count <= 0 {
			count = 1
		}
		acceptedCounts[entry.Hash] += count
	}

	filtered := make([]finding.FileFinding, 0, len(findings))
	for _, finding := range findings {
		hash := HashFinding(finding)
		if acceptedCounts[hash] > 0 {
			acceptedCounts[hash]--
			continue
		}
		filtered = append(filtered, finding)
	}

	return filtered
}

// Read loads a baseline snapshot file from disk.
func Read(path string) (Snapshot, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read baseline file %q: %w", path, err)
	}

	var snapshot Snapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("parse baseline file %q: %w", path, err)
	}

	if snapshot.Version != LegacySnapshotVersion && snapshot.Version != SnapshotVersion {
		return Snapshot{}, fmt.Errorf(
			"unsupported baseline version %d (expected %d or %d)",
			snapshot.Version,
			LegacySnapshotVersion,
			SnapshotVersion,
		)
	}
	for i := range snapshot.Entries {
		if snapshot.Entries[i].Count <= 0 {
			snapshot.Entries[i].Count = 1
		}
	}

	sort.SliceStable(snapshot.Entries, func(i, j int) bool {
		return snapshot.Entries[i].Hash < snapshot.Entries[j].Hash
	})

	return snapshot, nil
}

// Write saves a baseline snapshot to disk in a deterministic JSON format.
func Write(path string, snapshot Snapshot) error {
	snapshot.Version = SnapshotVersion
	sort.SliceStable(snapshot.Entries, func(i, j int) bool {
		return snapshot.Entries[i].Hash < snapshot.Entries[j].Hash
	})

	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline file %q: %w", path, err)
	}
	content = append(content, '\n')

	directory := filepath.Dir(path)
	if directory != "." && directory != "" {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("create baseline directory %q: %w", directory, err)
		}
	}

	if err := writeFileAtomically(path, content, 0o644, safefile.AtomicWriteOptions{
		TempPattern:              ".promptinel-baseline-*",
		RefuseDestinationSymlink: true,
	}); err != nil {
		return fmt.Errorf("write baseline file %q: %w", path, err)
	}

	return nil
}

func positionComesBefore(line int, column int, currentLine int, currentColumn int) bool {
	if line <= 0 {
		return false
	}
	if currentLine <= 0 {
		return true
	}
	if line != currentLine {
		return line < currentLine
	}
	return column < currentColumn
}
