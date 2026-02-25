package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/spf13/cobra"
)

func Test_Cmd_BaselineSnapshot_CreateWritesFile(t *testing.T) {
	workingDir := t.TempDir()
	prompt := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(prompt, []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	baselinePath := filepath.Join(workingDir, "baseline.json")
	if err := runBaselineSnapshot([]string{"."}, baselineOptions{file: baselinePath}, false); err != nil {
		t.Fatalf("create baseline snapshot: %v", err)
	}

	snapshot, err := baseline.Read(baselinePath)
	if err != nil {
		t.Fatalf("read baseline snapshot: %v", err)
	}
	if len(snapshot.Entries) == 0 {
		t.Fatal("expected baseline entries to be persisted")
	}
}

func Test_Cmd_BaselineSnapshot_UpdateRewritesFile(t *testing.T) {
	workingDir := t.TempDir()
	prompt := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(prompt, []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	baselinePath := filepath.Join(workingDir, "baseline.json")
	if err := runBaselineSnapshot([]string{"."}, baselineOptions{file: baselinePath}, false); err != nil {
		t.Fatalf("create baseline snapshot: %v", err)
	}

	if err := os.WriteFile(prompt, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("rewrite prompt file: %v", err)
	}
	if err := runBaselineSnapshot([]string{"."}, baselineOptions{file: baselinePath}, true); err != nil {
		t.Fatalf("update baseline snapshot: %v", err)
	}

	snapshot, err := baseline.Read(baselinePath)
	if err != nil {
		t.Fatalf("read updated baseline snapshot: %v", err)
	}
	if len(snapshot.Entries) != 0 {
		t.Fatalf("expected updated baseline to be empty after fix, got %d entries", len(snapshot.Entries))
	}
}

func Test_Cmd_BaselineOptionsFromCommand_ReadsFlags(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("file", baseline.DefaultFileName, "")

	if err := command.Flags().Set("config", "custom.yaml"); err != nil {
		t.Fatalf("set config flag: %v", err)
	}
	if err := command.Flags().Set("include", "*.md"); err != nil {
		t.Fatalf("set include flag: %v", err)
	}
	if err := command.Flags().Set("exclude", "*.txt"); err != nil {
		t.Fatalf("set exclude flag: %v", err)
	}
	if err := command.Flags().Set("file", "custom-baseline.json"); err != nil {
		t.Fatalf("set file flag: %v", err)
	}
	if err := command.Flags().Set("no-config-discovery", "true"); err != nil {
		t.Fatalf("set no-config-discovery flag: %v", err)
	}

	options, err := baselineOptionsFromCommand(command)
	if err != nil {
		t.Fatalf("read baseline options: %v", err)
	}

	if options.configFile != "custom.yaml" {
		t.Fatalf("expected config file custom.yaml, got %q", options.configFile)
	}
	if len(options.includes) != 1 || options.includes[0] != "*.md" {
		t.Fatalf("unexpected includes: %#v", options.includes)
	}
	if len(options.excludes) != 1 || options.excludes[0] != "*.txt" {
		t.Fatalf("unexpected excludes: %#v", options.excludes)
	}
	if options.file != "custom-baseline.json" {
		t.Fatalf("unexpected baseline file option: %q", options.file)
	}
	if !options.noConfigDiscovery {
		t.Fatal("expected no-config-discovery to be true")
	}
}

func Test_Cmd_RunBaselineUpdate_ReturnsErrorWhenFileMissing(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("file", baseline.DefaultFileName, "")

	if err := command.Flags().Set("file", filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("set baseline file flag: %v", err)
	}

	err := runBaselineUpdate(command, nil)
	if err == nil {
		t.Fatal("expected missing baseline file error")
	}
	if !strings.Contains(err.Error(), "stat baseline file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_Cmd_BaselineSnapshot_NoConfigDiscovery_IgnoresLocalConfig(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := `
policy:
  fail-on: low
  warn-on: low
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	prompt := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(prompt, []byte("http://example.com"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	withDiscoveryFile := filepath.Join(workingDir, "with-discovery.json")
	if err := runBaselineSnapshot([]string{"prompt.md"}, baselineOptions{file: withDiscoveryFile}, false); err != nil {
		t.Fatalf("create baseline with discovery: %v", err)
	}
	withDiscoverySnapshot, err := baseline.Read(withDiscoveryFile)
	if err != nil {
		t.Fatalf("read baseline with discovery: %v", err)
	}
	if len(withDiscoverySnapshot.Entries) == 0 {
		t.Fatal("expected at least one finding with discovered low warn-on policy")
	}

	withoutDiscoveryFile := filepath.Join(workingDir, "without-discovery.json")
	if err := runBaselineSnapshot([]string{"prompt.md"}, baselineOptions{file: withoutDiscoveryFile, noConfigDiscovery: true}, false); err != nil {
		t.Fatalf("create baseline without discovery: %v", err)
	}
	withoutDiscoverySnapshot, err := baseline.Read(withoutDiscoveryFile)
	if err != nil {
		t.Fatalf("read baseline without discovery: %v", err)
	}
	if len(withoutDiscoverySnapshot.Entries) != 0 {
		t.Fatalf("expected no findings with default medium warn-on policy, got %d", len(withoutDiscoverySnapshot.Entries))
	}
}
