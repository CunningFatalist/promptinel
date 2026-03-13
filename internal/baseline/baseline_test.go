package baseline

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	require.Contains(t, []int{1, 2}, snapshot.Entries[0].Count)
	require.Contains(t, []int{1, 2}, snapshot.Entries[1].Count)
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

func Test_Baseline_FilterFindings_MatchesAcrossPositionChanges(t *testing.T) {
	accepted := finding.FileFinding{
		Path: "a.md",
		Finding: rules.Finding{
			ID:       "rule-a",
			Severity: config.SeverityHigh,
			Message:  "accepted",
			Position: rules.Position{Line: 1, Column: 1},
		},
	}
	shifted := accepted
	shifted.Position = rules.Position{Line: 9, Column: 3}

	snapshot := BuildSnapshot([]finding.FileFinding{accepted})
	filtered := FilterFindings([]finding.FileFinding{shifted}, snapshot)

	require.Empty(t, filtered)
}

func Test_Baseline_FilterFindings_TracksRepeatedMatchesByCount(t *testing.T) {
	accepted := []finding.FileFinding{
		{
			Path: "a.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityHigh,
				Message:  "accepted",
				Position: rules.Position{Line: 1, Column: 1},
			},
		},
		{
			Path: "a.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityHigh,
				Message:  "accepted",
				Position: rules.Position{Line: 2, Column: 1},
			},
		},
	}
	candidate := append(append([]finding.FileFinding(nil), accepted...), finding.FileFinding{
		Path: "a.md",
		Finding: rules.Finding{
			ID:       "rule-a",
			Severity: config.SeverityHigh,
			Message:  "accepted",
			Position: rules.Position{Line: 3, Column: 1},
		},
	})

	snapshot := BuildSnapshot(accepted)
	filtered := FilterFindings(candidate, snapshot)

	require.Len(t, filtered, 1)
	assert.Equal(t, 3, filtered[0].Position.Line)
}

func Test_Baseline_FilterFindings_ReturnsInputWhenSnapshotEmpty(t *testing.T) {
	findings := []finding.FileFinding{
		{
			Path: "a.md",
			Finding: rules.Finding{
				ID:       "rule-a",
				Severity: config.SeverityLow,
				Message:  "message",
				Position: rules.Position{Line: 1, Column: 1},
			},
		},
	}

	filtered := FilterFindings(findings, Snapshot{})
	require.Equal(t, findings, filtered)
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
				Count:    1,
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
				Count:    1,
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
				Count:    1,
			},
		},
	}
	require.NoError(t, Write(file, replacement))

	loaded, err := Read(file)
	require.NoError(t, err)
	assert.Equal(t, replacement.Version, loaded.Version)
	assert.Equal(t, replacement.Entries, loaded.Entries)
}

func Test_Baseline_Read_ReturnsErrorWhenFileIsInvalidJSON(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")
	require.NoError(t, os.WriteFile(file, []byte("{invalid"), 0o644))

	_, err := Read(file)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse baseline file")
}

func Test_Baseline_Read_ReturnsErrorWhenFileMissing(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read baseline file")
}

func Test_Baseline_Read_ReturnsErrorWhenVersionIsUnsupported(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"version":999,"entries":[]}`), 0o644))

	_, err := Read(file)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported baseline version")
}

func Test_Baseline_Read_SortsEntriesByHash(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")
	content := `{"version":1,"entries":[{"hash":"zzz","path":"z.md","rule_id":"rule-z","severity":"high","message":"z","line":2,"column":1},{"hash":"aaa","path":"a.md","rule_id":"rule-a","severity":"low","message":"a","line":1,"column":1}]}`
	require.NoError(t, os.WriteFile(file, []byte(content), 0o644))

	snapshot, err := Read(file)
	require.NoError(t, err)
	require.Len(t, snapshot.Entries, 2)
	assert.Equal(t, "aaa", snapshot.Entries[0].Hash)
	assert.Equal(t, "zzz", snapshot.Entries[1].Hash)
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

func Test_Baseline_HashFinding_ChangesWhenFindingChanges(t *testing.T) {
	base := finding.FileFinding{
		Path: "a.md",
		Finding: rules.Finding{
			ID:       "rule-a",
			Severity: config.SeverityHigh,
			Message:  "msg",
			Position: rules.Position{Line: 10, Column: 8},
		},
	}
	changed := base
	changed.Message = "changed"

	assert.NotEqual(t, HashFinding(base), HashFinding(changed))
}

func Test_Baseline_HashFinding_IgnoresPositionChanges(t *testing.T) {
	base := finding.FileFinding{
		Path: "a.md",
		Finding: rules.Finding{
			ID:       "rule-a",
			Severity: config.SeverityHigh,
			Message:  "msg",
			Position: rules.Position{Line: 10, Column: 8},
		},
	}
	changed := base
	changed.Position = rules.Position{Line: 11, Column: 1}

	assert.Equal(t, HashFinding(base), HashFinding(changed))
}

func Test_Baseline_Read_AcceptsLegacyVersion(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")
	content := `{"version":1,"entries":[{"hash":"legacy","path":"a.md","rule_id":"rule-a","severity":"high","message":"m","line":1,"column":1}]}`
	require.NoError(t, os.WriteFile(file, []byte(content), 0o644))

	snapshot, err := Read(file)
	require.NoError(t, err)
	assert.Equal(t, LegacySnapshotVersion, snapshot.Version)
	require.Len(t, snapshot.Entries, 1)
	assert.Equal(t, 1, snapshot.Entries[0].Count)
}

func Test_Baseline_Write_CreatesParentDirectoryAndNormalizesVersion(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nested", "baseline.json")
	snapshot := Snapshot{
		Version: 0,
		Entries: []Entry{
			{
				Hash:     "hash",
				Path:     "a.md",
				RuleID:   "rule-a",
				Severity: config.SeverityMedium,
				Message:  "msg",
				Line:     2,
				Column:   3,
			},
		},
	}

	require.NoError(t, Write(file, snapshot))
	loaded, err := Read(file)
	require.NoError(t, err)
	assert.Equal(t, SnapshotVersion, loaded.Version)
	assert.DirExists(t, filepath.Dir(file))
}

func Test_Baseline_Write_SortsEntriesBeforePersisting(t *testing.T) {
	file := filepath.Join(t.TempDir(), "baseline.json")
	snapshot := Snapshot{
		Version: SnapshotVersion,
		Entries: []Entry{
			{
				Hash:     "zzz",
				Path:     "z.md",
				RuleID:   "rule-z",
				Severity: config.SeverityHigh,
				Message:  "z",
				Line:     3,
				Column:   1,
			},
			{
				Hash:     "aaa",
				Path:     "a.md",
				RuleID:   "rule-a",
				Severity: config.SeverityLow,
				Message:  "a",
				Line:     1,
				Column:   1,
			},
		},
	}

	require.NoError(t, Write(file, snapshot))

	content, err := os.ReadFile(file)
	require.NoError(t, err)
	text := string(content)
	assert.Less(t, strings.Index(text, `"hash": "aaa"`), strings.Index(text, `"hash": "zzz"`))
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

func Test_Baseline_Write_ReturnsErrorWhenParentPathIsAFile(t *testing.T) {
	workingDir := t.TempDir()
	parentPath := filepath.Join(workingDir, "not-a-directory")
	require.NoError(t, os.WriteFile(parentPath, []byte("fixture"), 0o644))

	err := Write(filepath.Join(parentPath, "baseline.json"), Snapshot{
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
	assert.Contains(t, err.Error(), "create baseline directory")
}
