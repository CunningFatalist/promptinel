package sanitize

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/safefile"
)

func Test_Sanitize_Run_ReturnsCanceledContextWhenAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, Request{Paths: []string{"."}, Discover: false})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func Test_Sanitize_Run_DryRunReportsPlannedChanges(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	content := "line1\r\nline2\u200b\r\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousWorkingDir) })

	result, err := Run(context.Background(), Request{Paths: []string{"."}, Discover: true, Include: []string{"*.md"}})
	if err != nil {
		t.Fatalf("run sanitize: %v", err)
	}

	if result.Summary.Changed != 1 {
		t.Fatalf("expected changed files=1, got %d", result.Summary.Changed)
	}
	if len(result.Events) == 0 || result.Events[0].Action != ActionWouldSanitize {
		t.Fatalf("expected would sanitize event, got %#v", result.Events)
	}

	persisted, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read fixture after dry-run: %v", err)
	}
	if string(persisted) != content {
		t.Fatalf("expected dry-run to keep original content, got %q", string(persisted))
	}
}

func Test_Sanitize_Run_ApplyWritesChanges(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\nline2\u200b\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	result, err := Run(context.Background(), Request{Paths: []string{workingDir}, Discover: true, Include: []string{"*.md"}, Apply: true})
	if err != nil {
		t.Fatalf("run sanitize --apply: %v", err)
	}
	if !result.Summary.Applied {
		t.Fatal("expected applied summary to be true")
	}
	if len(result.Events) != 1 || result.Events[0].Action != ActionSanitized {
		t.Fatalf("expected sanitized event, got %#v", result.Events)
	}

	persisted, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read fixture after apply: %v", err)
	}
	if string(persisted) != "line1\nline2\n" {
		t.Fatalf("unexpected sanitized content: %q", string(persisted))
	}
}

func Test_Sanitize_Run_SkipsOversizedFile(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	if err := os.WriteFile(configPath, []byte("limits:\n  max_file_size_bytes: 1\n"), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	result, err := Run(context.Background(), Request{Paths: []string{workingDir}, ConfigFile: configPath, Discover: false})
	if err != nil {
		t.Fatalf("run sanitize: %v", err)
	}

	foundPromptSizeSkip := false
	for _, event := range result.Events {
		if filepath.Base(event.Path) == "prompt.md" &&
			event.Action == ActionSkipped &&
			strings.Contains(event.Reason, "exceeds limits.max_file_size_bytes=1") {
			foundPromptSizeSkip = true
		}
	}
	if !foundPromptSizeSkip {
		t.Fatalf("expected prompt.md max size skip, got %#v", result.Events)
	}
}

func Test_Sanitize_Run_UnchangedFileProducesNoEvents(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	result, err := Run(context.Background(), Request{Paths: []string{workingDir}, Discover: false})
	if err != nil {
		t.Fatalf("run sanitize: %v", err)
	}
	if result.Summary.Files != 1 || result.Summary.Changed != 0 {
		t.Fatalf("unexpected summary: %#v", result.Summary)
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected no events for unchanged file, got %#v", result.Events)
	}
}

func Test_Sanitize_Run_NoConfigDiscovery_IgnoresLocalConfig(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "limits:\n  max_file_size_bytes: 1\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousWorkingDir) })

	withDiscovery, err := Run(context.Background(), Request{Paths: []string{"."}, Discover: true})
	if err != nil {
		t.Fatalf("run sanitize with discovery: %v", err)
	}
	foundLimitSkip := false
	for _, event := range withDiscovery.Events {
		if event.Action == ActionSkipped && strings.Contains(event.Reason, "exceeds limits.max_file_size_bytes=1") {
			foundLimitSkip = true
		}
	}
	if !foundLimitSkip {
		t.Fatalf("expected discovered config max file size skip, events: %#v", withDiscovery.Events)
	}

	withoutDiscovery, err := Run(context.Background(), Request{Paths: []string{"."}, Discover: false})
	if err != nil {
		t.Fatalf("run sanitize without discovery: %v", err)
	}
	foundWouldSanitize := false
	for _, event := range withoutDiscovery.Events {
		if event.Action == ActionWouldSanitize {
			foundWouldSanitize = true
		}
	}
	if !foundWouldSanitize {
		t.Fatalf("expected sanitize to proceed with defaults, events: %#v", withoutDiscovery.Events)
	}
}

func Test_Sanitize_Run_CLIIncludeOverridesConfigFilters(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "filters:\n  include:\n    - \"*.md\"\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "excluded-by-cli.md"), []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write markdown file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "included-by-cli.txt"), []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write txt file: %v", err)
	}

	result, err := Run(context.Background(), Request{
		Paths:      []string{workingDir},
		ConfigFile: configPath,
		Discover:   false,
		Include:    []string{"*.txt"},
		IncludeSet: true,
	})
	if err != nil {
		t.Fatalf("run sanitize: %v", err)
	}

	for _, event := range result.Events {
		if strings.Contains(event.Path, "excluded-by-cli.md") && event.Action == ActionWouldSanitize {
			t.Fatalf("expected markdown file to be excluded by CLI override, events: %#v", result.Events)
		}
	}
}

func Test_Sanitize_Run_SkipsSymlinkInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	target := filepath.Join(workingDir, "target.md")
	if err := os.WriteFile(target, []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	link := filepath.Join(workingDir, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	result, err := Run(context.Background(), Request{Paths: []string{link}, Discover: false})
	if err != nil {
		t.Fatalf("run sanitize: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].Action != ActionSkipped {
		t.Fatalf("expected one skipped event, got %#v", result.Events)
	}
	if result.Events[0].Reason != "symbolic links are not sanitized" {
		t.Fatalf("unexpected skip reason: %#v", result.Events)
	}
}

func Test_Sanitize_Run_ReturnsErrorWhenCollectionFails(t *testing.T) {
	_, err := Run(context.Background(), Request{
		Paths:    []string{"/definitely/missing/path"},
		Discover: false,
	})
	if err == nil {
		t.Fatal("expected collect files error")
	}
	if !strings.Contains(err.Error(), "collect files") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_Sanitize_Run_ReturnsErrorWhenAtomicWriteFails(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	originalWriter := writeFileAtomically
	writeFileAtomically = func(_ string, _ []byte, _ os.FileMode, _ safefile.AtomicWriteOptions) error {
		return errors.New("forced write failure")
	}
	t.Cleanup(func() {
		writeFileAtomically = originalWriter
	})

	_, err := Run(context.Background(), Request{Paths: []string{workingDir}, Discover: false, Apply: true})
	if err == nil {
		t.Fatal("expected write failure error")
	}
	if !strings.Contains(err.Error(), "write sanitized file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "forced write failure") {
		t.Fatalf("expected forced write failure in error, got: %v", err)
	}
}
