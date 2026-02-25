package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func Test_Cmd_SanitizeWithOptions_DryRunPrintsPlannedChanges(t *testing.T) {
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
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	output := captureStdout(t, func() {
		runErr := runSanitizeWithOptions([]string{"."}, sanitizeOptions{
			includes: []string{"*.md"},
		})
		if runErr != nil {
			t.Fatalf("run sanitize: %v", runErr)
		}
	})

	if !strings.Contains(output, "would sanitize") {
		t.Fatalf("expected dry-run output, got %q", output)
	}

	persisted, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read fixture after dry-run: %v", err)
	}
	if string(persisted) != content {
		t.Fatalf("expected dry-run to keep original content, got %q", string(persisted))
	}
}

func Test_Cmd_SanitizeWithOptions_ApplyWritesChanges(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\nline2\u200b\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
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

	if err := runSanitizeWithOptions([]string{"."}, sanitizeOptions{
		includes: []string{"*.md"},
		apply:    true,
	}); err != nil {
		t.Fatalf("run sanitize --apply: %v", err)
	}

	persisted, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read fixture after apply: %v", err)
	}

	if string(persisted) != "line1\nline2\n" {
		t.Fatalf("unexpected sanitized content: %q", string(persisted))
	}
}

func Test_Cmd_SanitizeOptionsFromCommand_ReadsFlags(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")

	if err := command.Flags().Set("config", "custom.yaml"); err != nil {
		t.Fatalf("set config flag: %v", err)
	}
	if err := command.Flags().Set("include", "*.md"); err != nil {
		t.Fatalf("set include flag: %v", err)
	}
	if err := command.Flags().Set("exclude", "*.txt"); err != nil {
		t.Fatalf("set exclude flag: %v", err)
	}
	if err := command.Flags().Set("apply", "true"); err != nil {
		t.Fatalf("set apply flag: %v", err)
	}

	options, err := sanitizeOptionsFromCommand(command)
	if err != nil {
		t.Fatalf("read sanitize options: %v", err)
	}

	if options.configFile != "custom.yaml" {
		t.Fatalf("expected config file custom.yaml, got %q", options.configFile)
	}
	if !options.apply {
		t.Fatal("expected apply option to be true")
	}
	if len(options.includes) != 1 || options.includes[0] != "*.md" {
		t.Fatalf("unexpected includes: %#v", options.includes)
	}
	if len(options.excludes) != 1 || options.excludes[0] != "*.txt" {
		t.Fatalf("unexpected excludes: %#v", options.excludes)
	}
}
