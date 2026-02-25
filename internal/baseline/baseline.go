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
	"github.com/CunningFatalist/promptinel/internal/engine"
)

const (
	// DefaultFileName is the default baseline snapshot file path.
	DefaultFileName = ".promptinel-baseline.json"
	// SnapshotVersion is the current baseline file format version.
	SnapshotVersion = 1
)

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
}

// BuildSnapshot converts findings into a deterministic baseline snapshot.
func BuildSnapshot(findings []engine.FileFinding) Snapshot {
	entriesByHash := make(map[string]Entry, len(findings))
	for _, finding := range findings {
		hash := HashFinding(finding)
		entriesByHash[hash] = Entry{
			Hash:     hash,
			Path:     finding.Path,
			RuleID:   finding.ID,
			Severity: finding.Severity,
			Message:  finding.Message,
			Line:     finding.Position.Line,
			Column:   finding.Position.Column,
		}
	}

	entries := make([]Entry, 0, len(entriesByHash))
	for _, entry := range entriesByHash {
		entries = append(entries, entry)
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Hash != entries[j].Hash {
			return entries[i].Hash < entries[j].Hash
		}
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		if entries[i].Line != entries[j].Line {
			return entries[i].Line < entries[j].Line
		}
		if entries[i].Column != entries[j].Column {
			return entries[i].Column < entries[j].Column
		}
		if entries[i].RuleID != entries[j].RuleID {
			return entries[i].RuleID < entries[j].RuleID
		}
		if entries[i].Severity != entries[j].Severity {
			return entries[i].Severity < entries[j].Severity
		}
		return entries[i].Message < entries[j].Message
	})

	return Snapshot{
		Version: SnapshotVersion,
		Entries: entries,
	}
}

// HashFinding returns a deterministic hash for one finding.
func HashFinding(finding engine.FileFinding) string {
	payload := strings.Join([]string{
		finding.Path,
		finding.ID,
		finding.Severity.String(),
		finding.Message,
		fmt.Sprintf("%d", finding.Position.Line),
		fmt.Sprintf("%d", finding.Position.Column),
	}, "\n")

	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// FilterFindings removes findings already accepted by the provided snapshot.
func FilterFindings(findings []engine.FileFinding, snapshot Snapshot) []engine.FileFinding {
	if len(snapshot.Entries) == 0 {
		return findings
	}

	accepted := make(map[string]struct{}, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		accepted[entry.Hash] = struct{}{}
	}

	filtered := make([]engine.FileFinding, 0, len(findings))
	for _, finding := range findings {
		if _, ok := accepted[HashFinding(finding)]; ok {
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

	if snapshot.Version != SnapshotVersion {
		return Snapshot{}, fmt.Errorf("unsupported baseline version %d (expected %d)", snapshot.Version, SnapshotVersion)
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

	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("write baseline file %q: %w", path, err)
	}

	return nil
}
