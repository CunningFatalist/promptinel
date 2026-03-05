package baseline

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/finding"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/safefile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Baseline_BuildSnapshot_DeduplicatesAndSortsDeterministically(t *testing.T) {
	findings := []finding.FileFinding{
		{
			Path: "b.md",
			Finding: rules.Finding{
				ID:       "rule-b",
				Severity: config.SeverityMedium,
				Message:  "message b",
				Position: rules.Position{Line: 2, Column: 1},
			},
		},
		{
			Path: "a.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityLow,
				Message:  "message a",
				Position: rules.Position{Line: 1, Column: 1},
			},
		},
		{
			Path: "a.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityLow,
				Message:  "message a",
				Position: rules.Position{Line: 1, Column: 1},
			},
		},
	}

	snapshot := BuildSnapshot(findings)

	assert.Equal(t, SnapshotVersion, snapshot.Version)
	require.Len(t, snapshot.Entries, 2)
	assert.LessOrEqual(t, snapshot.Entries[0].Hash, snapshot.Entries[1].Hash)
}

func Test_Baseline_FilterFindings_RemovesAcceptedEntries(t *testing.T) {
	accepted := finding.FileFinding{
		Path: "a.md",
		Finding: rules.Finding{
			ID:       "rule-a",
			Severity: config.SeverityHigh,
			Message:  "accepted",
			Position: rules.Position{Line: 1, Column: 1},
		},
	}
	newFinding := finding.FileFinding{
		Path: "b.md",
		Finding: rules.Finding{
			ID:       "rule-b",
			Severity: config.SeverityLow,
			Message:  "new",
			Position: rules.Position{Line: 3, Column: 2},
		},
	}

	snapshot := BuildSnapshot([]finding.FileFinding{accepted})
	filtered := FilterFindings([]finding.FileFinding{accepted, newFinding}, snapshot)

	require.Len(t, filtered, 1)
	assert.Equal(t, newFinding.Path, filtered[0].Path)
	assert.Equal(t, newFinding.ID, filtered[0].ID)
}

func Test_Baseline_ReadWrite_RoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Entries: []Entry{
			{
				Hash:     "abc",
				Path:     "a.md",
				RuleID:   "rule-a",
				Severity: config.SeverityMedium,
				Message:  "msg",
				Line:     4,
				Column:   2,
			},
		},
	}

	require.NoError(t, Write(file, snapshot))
	loaded, err := Read(file)
	require.NoError(t, err)

	assert.Equal(t, snapshot.Version, loaded.Version)
	assert.Equal(t, snapshot.Entries, loaded.Entries)
}

func Test_Baseline_Write_OverwritesExistingFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")

	original := Snapshot{
		Version: SnapshotVersion,
		Entries: []Entry{
			{
				Hash:     "abc",
				Path:     "a.md",
				RuleID:   "rule-a",
				Severity: config.SeverityLow,
				Message:  "original",
				Line:     1,
				Column:   1,
			},
		},
	}
	require.NoError(t, Write(file, original))

	replacement := Snapshot{
		Version: SnapshotVersion,
		Entries: []Entry{
			{
				Hash:     "def",
				Path:     "b.md",
				RuleID:   "rule-b",
				Severity: config.SeverityHigh,
				Message:  "replacement",
				Line:     7,
				Column:   3,
			},
		},
	}
	require.NoError(t, Write(file, replacement))

	loaded, err := Read(file)
	require.NoError(t, err)
	assert.Equal(t, replacement.Version, loaded.Version)
	assert.Equal(t, replacement.Entries, loaded.Entries)
}

func Test_Baseline_HashFinding_IsDeterministic(t *testing.T) {
	finding := finding.FileFinding{
		Path: "a.md",
		Finding: rules.Finding{
			ID:       "rule-a",
			Severity: config.SeverityHigh,
			Message:  "msg",
			Position: rules.Position{Line: 10, Column: 8},
		},
	}

	first := HashFinding(finding)
	second := HashFinding(finding)
	assert.Equal(t, first, second)
}

func Test_Baseline_Write_RejectsSymlinkDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	victimPath := filepath.Join(workingDir, "victim.json")
	require.NoError(t, os.WriteFile(victimPath, []byte("victim-original"), 0o644))

	linkPath := filepath.Join(workingDir, "baseline-link.json")
	require.NoError(t, os.Symlink(victimPath, linkPath))

	err := Write(linkPath, Snapshot{
		Version: SnapshotVersion,
		Entries: []Entry{
			{
				Hash:     "abc",
				Path:     "a.md",
				RuleID:   "rule-a",
				Severity: config.SeverityLow,
				Message:  "message",
				Line:     1,
				Column:   1,
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symbolic link")

	victimContent, readErr := os.ReadFile(victimPath)
	require.NoError(t, readErr)
	assert.Equal(t, "victim-original", string(victimContent))
}

func Test_Baseline_Write_ReturnsErrorWhenAtomicWriteFails(t *testing.T) {
	originalWriter := writeFileAtomically
	writeFileAtomically = func(_ string, _ []byte, _ os.FileMode, _ safefile.AtomicWriteOptions) error {
		return errors.New("forced write failure")
	}
	t.Cleanup(func() {
		writeFileAtomically = originalWriter
	})

	err := Write(filepath.Join(t.TempDir(), "baseline.json"), Snapshot{
		Version: SnapshotVersion,
		Entries: []Entry{
			{
				Hash:     "abc",
				Path:     "a.md",
				RuleID:   "rule-a",
				Severity: config.SeverityLow,
				Message:  "message",
				Line:     1,
				Column:   1,
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forced write failure")
}
