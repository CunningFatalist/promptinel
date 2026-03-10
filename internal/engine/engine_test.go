package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Engine_ScanPaths_AppliesIncludeAndExcludePatterns(t *testing.T) {
	tmp := t.TempDir()
	keep := filepath.Join(tmp, "keep.md")
	skip := filepath.Join(tmp, "skip.txt")
	require.NoError(t, os.WriteFile(keep, []byte("a"), 0o644))
	require.NoError(t, os.WriteFile(skip, []byte("b"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("always", config.SeverityMedium, "found"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	scanner := NewScanner(compiled, config.DefaultConfig())
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, []string{"*.md"}, []string{"skip*"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "keep.md", filepath.Base(findings[0].Path))
}

func Test_Engine_ScanPaths_ReturnsErrorForMissingPath(t *testing.T) {
	scanner := NewScanner(nil, config.DefaultConfig())
	_, err := scanner.ScanPaths(context.Background(), []string{"/does/not/exist"}, nil, nil)
	require.Error(t, err)
}

func Test_Engine_ScanPaths_UsesSharedFilterMatching(t *testing.T) {
	assert.True(t, filters.Match("a.md", nil, nil))
	assert.False(t, filters.Match("a.txt", []string{"*.md"}, nil))
	assert.False(t, filters.Match("a.md", []string{"*.md"}, []string{"a.*"}))
	assert.True(t, filters.Match("docs/a/b.md", []string{"docs/**"}, nil))
	assert.False(t, filters.Match("docs/a/b.md", nil, []string{"docs/**"}))
}

func Test_Engine_ScanPaths_ContextCanceled(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "f.md")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("always", config.SeverityLow, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	scanner := NewScanner(compiled, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = scanner.ScanPaths(ctx, []string{tmp}, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func Test_Engine_ScanPaths_CancellationReturnsPromptlyOnLargeInputSet(t *testing.T) {
	tmp := t.TempDir()
	totalFiles := max(runtime.GOMAXPROCS(0)*4, 8)

	for i := range totalFiles {
		file := filepath.Join(tmp, fmt.Sprintf("file-%03d.md", i))
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	}

	var startedChecks atomic.Int32
	registry := rules.NewRegistry()
	err := registry.Register(slowRuleForTest{
		id:            "slow",
		defaultSev:    config.SeverityLow,
		sleep:         500 * time.Millisecond,
		startedChecks: &startedChecks,
	})
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	scanner := NewScanner(compiled, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, scanErr := scanner.ScanPaths(ctx, []string{tmp}, nil, nil)
		done <- scanErr
	}()

	deadline := time.Now().Add(2 * time.Second)
	for startedChecks.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if startedChecks.Load() == 0 {
		t.Fatal("expected at least one rule evaluation to start before cancellation")
	}

	cancelAt := time.Now()
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Less(t, time.Since(cancelAt), 300*time.Millisecond, "scan should stop promptly after cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scan cancellation")
	}
}

func Test_Engine_scanTargets_ContextCanceledBeforeDispatch(t *testing.T) {
	scanner := NewScanner(nil, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.scanTargets(ctx, []scanTarget{{
		index:        0,
		absolutePath: "/tmp/file.md",
		relativePath: "file.md",
	}}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func Test_Engine_ScanPaths_SkipsOversizedFileWithExplicitFinding(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "large.md")
	require.NoError(t, os.WriteFile(file, []byte("123456789"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("always", config.SeverityHigh, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Limits.MaxFileSizeBytes = 4

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, oversizedFileFindingID, findings[0].ID)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
	assert.Contains(t, findings[0].Message, "File skipped")
	assert.Equal(t, 1, findings[0].Position.Line)
	assert.Equal(t, 1, findings[0].Position.Column)
}

func Test_Engine_ScanDocument_SkipsOversizedContentWithExplicitFinding(t *testing.T) {
	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("always", config.SeverityHigh, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Limits.MaxFileSizeBytes = 4

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanDocument(context.Background(), Document{
		Path:    "inline.md",
		Content: "12345",
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, oversizedFileFindingID, findings[0].ID)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
	assert.Equal(t, "inline.md", findings[0].Path)
}

func Test_Engine_ScanDocument_AppliesScopeSeverityOverride(t *testing.T) {
	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("always", config.SeverityHigh, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{Path: "docs/**", Severity: config.SeverityLow},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanDocument(context.Background(), Document{
		Path:    "docs/inline.md",
		Content: "x",
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
}

func Test_Engine_ScanDocument_ContextCanceled(t *testing.T) {
	scanner := NewScanner(nil, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.ScanDocument(ctx, Document{Content: "x"})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func Test_Engine_ScanPaths_AppliesScopeSeverityOverride(t *testing.T) {
	tmp := t.TempDir()
	nestedDir := filepath.Join(tmp, "docs", "nested")
	require.NoError(t, os.MkdirAll(nestedDir, 0o755))
	file := filepath.Join(nestedDir, "file.md")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	previousWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})

	registry := rules.NewRegistry()
	err = registry.Register(newAlwaysRule("always", config.SeverityHigh, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{Path: "docs/**", Severity: config.SeverityLow},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
}

func Test_Engine_ScanPaths_AppliesScopeSeverityOverride_WhenWorkingDirectoryDiffersFromScanRoot(t *testing.T) {
	base := t.TempDir()
	scanRoot := filepath.Join(base, "repo")
	require.NoError(t, os.MkdirAll(filepath.Join(scanRoot, "docs", "nested"), 0o755))

	file := filepath.Join(scanRoot, "docs", "nested", "file.md")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	previousWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(base))
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})

	registry := rules.NewRegistry()
	err = registry.Register(newAlwaysRule("always", config.SeverityHigh, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{Path: "docs/**", Severity: config.SeverityLow},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{scanRoot}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
}

func Test_Engine_ScanPaths_AppliesScopeSeverityOverride_ForSingleFilePathOutsideWorkingDirectory(t *testing.T) {
	base := t.TempDir()
	scanRoot := filepath.Join(base, "repo")
	require.NoError(t, os.MkdirAll(filepath.Join(scanRoot, "docs", "nested"), 0o755))

	file := filepath.Join(scanRoot, "docs", "nested", "file.md")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	previousWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(base))
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})

	registry := rules.NewRegistry()
	err = registry.Register(newAlwaysRule("always", config.SeverityHigh, "m"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{Path: "docs/**", Severity: config.SeverityLow},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{file}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
}

func Test_Engine_ScanPaths_AppliesScopedRuleDisable(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "docs", "file.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("rule-a", config.SeverityMedium, "a"))
	require.NoError(t, err)
	err = registry.Register(newAlwaysRule("rule-b", config.SeverityMedium, "b"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	disabled := false
	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{
			Path: "docs/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &disabled},
			},
		},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "rule-b", findings[0].ID)
}

func Test_Engine_ScanPaths_DetectsReferencedSkillResources(t *testing.T) {
	tmp := t.TempDir()
	skillDir := filepath.Join(tmp, "skills", "demo")
	require.NoError(t, os.MkdirAll(filepath.Join(skillDir, "scripts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "scripts", "run.py"), []byte("print('ok')\n"), 0o644))

	skillDoc := `---
name: demo
description: demo
---

Use [runner](scripts/run.py) to execute the workflow.
`
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skillDoc), 0o644))

	registry, err := builtin.NewRegistry()
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	scanner := NewScanner(compiled, config.DefaultConfig())
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.True(t, filepath.ToSlash(findings[0].Path) == "skills/demo/SKILL.md" || strings.HasSuffix(filepath.ToSlash(findings[0].Path), "/skills/demo/SKILL.md"))
	assert.Equal(t, "skill-has-bundled-resources", findings[0].ID)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
	assert.Contains(t, findings[0].Message, "scripts/run.py")
}

func Test_Engine_ScanPaths_IgnoresUnresolvedSkillReferences(t *testing.T) {
	tmp := t.TempDir()
	skillDir := filepath.Join(tmp, "skills", "demo")
	require.NoError(t, os.MkdirAll(skillDir, 0o755))

	skillDoc := `Use [runner](scripts/run.py) only after setup.`
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skillDoc), 0o644))

	registry, err := builtin.NewRegistry()
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	scanner := NewScanner(compiled, config.DefaultConfig())
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func Test_Engine_ScanPaths_AppliesScopedRuleSeverityOverride(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "docs", "file.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("rule-a", config.SeverityHigh, "a"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{
			Path:     "docs/**",
			Severity: config.SeverityLow,
			Rules: []config.Rule{
				{ID: "rule-a", Severity: config.SeverityMedium},
			},
		},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, config.SeverityMedium, findings[0].Severity)
}

func Test_Engine_ScanPaths_AppliesOverlappingScopePrecedence_LastWins(t *testing.T) {
	tmp := t.TempDir()
	rootFile := filepath.Join(tmp, "docs", "root.md")
	securityFile := filepath.Join(tmp, "docs", "security", "deep.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(securityFile), 0o755))
	require.NoError(t, os.WriteFile(rootFile, []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(securityFile, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("rule-a", config.SeverityMedium, "a"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	disabled := false
	enabled := true
	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{
			Path: "docs/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &disabled},
			},
		},
		{
			Path: "docs/security/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &enabled, Severity: config.SeverityHigh},
			},
		},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, filepath.ToSlash(findings[0].Path), "docs/security/deep.md")
	assert.Equal(t, config.SeverityHigh, findings[0].Severity)
}

func Test_Engine_ScanPaths_AppliesMultipleScopedRuleOverrides_LastWins(t *testing.T) {
	tmp := t.TempDir()
	securityFile := filepath.Join(tmp, "docs", "security", "note.md")
	criticalFile := filepath.Join(tmp, "docs", "security", "critical", "runbook.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(criticalFile), 0o755))
	require.NoError(t, os.WriteFile(securityFile, []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(criticalFile, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("rule-a", config.SeverityLow, "a"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	enabled := true
	disabled := false
	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{
			Path: "docs/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &enabled, Severity: config.SeverityLow},
			},
		},
		{
			Path: "docs/security/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &disabled, Severity: config.SeverityMedium},
			},
		},
		{
			Path: "docs/security/critical/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &enabled, Severity: config.SeverityHigh},
			},
		},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, filepath.ToSlash(findings[0].Path), "docs/security/critical/runbook.md")
	assert.Equal(t, "rule-a", findings[0].ID)
	assert.Equal(t, config.SeverityHigh, findings[0].Severity)
}

func Test_Engine_ScanPaths_PreservesScopedRuleDisableOnSeverityOnlyOverride(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "docs", "security", "deep.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("rule-a", config.SeverityLow, "a"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	disabled := false
	cfg := config.DefaultConfig()
	cfg.Scopes = []config.Scope{
		{
			Path: "docs/**",
			Rules: []config.Rule{
				{ID: "rule-a", Enabled: &disabled},
			},
		},
		{
			Path: "docs/security/**",
			Rules: []config.Rule{
				{ID: "rule-a", Severity: config.SeverityHigh},
			},
		},
	}

	scanner := NewScanner(compiled, cfg)
	findings, err := scanner.ScanPaths(context.Background(), []string{tmp}, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func Test_Engine_ScanPaths_PreservesInputOrderWithConcurrentWorkers(t *testing.T) {
	tmp := t.TempDir()
	first := filepath.Join(tmp, "first.md")
	second := filepath.Join(tmp, "second.md")
	require.NoError(t, os.WriteFile(first, []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(second, []byte("x"), 0o644))

	registry := rules.NewRegistry()
	err := registry.Register(newAlwaysRule("always", config.SeverityMedium, "found"))
	require.NoError(t, err)
	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	scanner := NewScanner(compiled, config.DefaultConfig())
	findings, err := scanner.ScanPaths(context.Background(), []string{second, first}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, filepath.Base(second), filepath.Base(findings[0].Path))
	assert.Equal(t, filepath.Base(first), filepath.Base(findings[1].Path))
}

func Test_Engine_ScanPaths_SkipsSymlinkedInputAsNonFatalFinding(t *testing.T) {
	tmp := t.TempDir()
	link := filepath.Join(tmp, "broken.md")
	require.NoError(t, os.Symlink(filepath.Join(tmp, "missing.md"), link))

	scanner := NewScanner(nil, config.DefaultConfig())
	findings, err := scanner.ScanPaths(context.Background(), []string{link}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, unreadableFileFindingID, findings[0].ID)
	assert.Contains(t, findings[0].Message, "symbolic links are not scanned")
}

func Test_Engine_ScanPaths_NonRegularInputBecomesSkipFinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are not supported in this test on windows")
	}

	tmp := t.TempDir()
	pipePath := filepath.Join(tmp, "scan.fifo")
	require.NoError(t, syscall.Mkfifo(pipePath, 0o600))

	scanner := NewScanner(nil, config.DefaultConfig())
	findings, err := scanner.ScanPaths(context.Background(), []string{pipePath}, nil, nil)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, unreadableFileFindingID, findings[0].ID)
	assert.Contains(t, findings[0].Message, "non-regular file")
}

func Test_Engine_IsOversizedFileSkipFinding(t *testing.T) {
	assert.True(t, IsOversizedFileSkipFinding(FileFinding{
		Finding: rules.Finding{ID: oversizedFileFindingID},
	}))
	assert.False(t, IsOversizedFileSkipFinding(FileFinding{
		Finding: rules.Finding{ID: unreadableFileFindingID},
	}))
}

type slowRuleForTest struct {
	id            string
	defaultSev    config.Severity
	sleep         time.Duration
	startedChecks *atomic.Int32
}

func (r slowRuleForTest) Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              r.id,
		DefaultSeverity: r.defaultSev,
	}
}

func (r slowRuleForTest) CheckDocument(_ rules.Context, _ rules.DocumentView) []rules.Finding {
	r.startedChecks.Add(1)
	time.Sleep(r.sleep)
	return []rules.Finding{{
		Message:  "slow finding",
		Position: rules.Position{Line: 1, Column: 1},
	}}
}
