package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/spf13/cobra"
)

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

func Test_Cmd_BaselineSnapshot_UsesRawFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	link := filepath.Join(workingDir, "broken.md")
	if err := os.Symlink(filepath.Join(workingDir, "missing.md"), link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	baselinePath := filepath.Join(workingDir, "baseline.json")

	if err := runBaselineSnapshot(context.Background(), []string{link}, baselineOptions{file: baselinePath, noConfigDiscovery: true}, false); err != nil {
		t.Fatalf("create baseline snapshot: %v", err)
	}

	snapshot, err := baseline.Read(baselinePath)
	if err != nil {
		t.Fatalf("read baseline snapshot: %v", err)
	}
	if len(snapshot.Entries) == 0 {
		t.Fatalf("expected baseline snapshot entries from raw findings, got %#v", snapshot)
	}
}

func Test_Cmd_RunBaselineCreate_UsesCommandContext(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("file", baseline.DefaultFileName, "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command.SetContext(ctx)

	err := runBaselineCreate(command, []string{file})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
