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
	_ = os.WriteFile(prompt, []byte("hello\u200bworld"), 0o644)

	baselinePath := filepath.Join(workingDir, "baseline.json")
	if err := runBaselineSnapshot([]string{workingDir}, baselineOptions{file: baselinePath, noConfigDiscovery: true}, false); err != nil {
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

func Test_Cmd_ParseBaselineOptions_ReadsFlags(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("file", baseline.DefaultFileName, "")

	_ = command.Flags().Set("config", "custom.yaml")
	_ = command.Flags().Set("include", "*.md")
	_ = command.Flags().Set("exclude", "*.txt")
	_ = command.Flags().Set("file", "custom-baseline.json")
	_ = command.Flags().Set("no-config-discovery", "true")

	options, err := parseBaselineOptions(command)
	if err != nil {
		t.Fatalf("read baseline options: %v", err)
	}
	if options.configFile != "custom.yaml" || options.file != "custom-baseline.json" {
		t.Fatalf("unexpected options: %#v", options)
	}
}

func Test_Cmd_RunBaselineUpdate_ReturnsErrorWhenFileMissing(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("file", baseline.DefaultFileName, "")
	_ = command.Flags().Set("file", filepath.Join(t.TempDir(), "missing.json"))

	err := runBaselineUpdate(command, nil)
	if err == nil {
		t.Fatal("expected missing baseline file error")
	}
	if !strings.Contains(err.Error(), "stat baseline file") {
		t.Fatalf("unexpected error: %v", err)
	}
}
