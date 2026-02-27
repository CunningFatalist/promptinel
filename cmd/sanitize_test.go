package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func Test_Cmd_ParseSanitizeOptions_ReadsFlags(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")

	_ = command.Flags().Set("config", "custom.yaml")
	_ = command.Flags().Set("include", "*.md")
	_ = command.Flags().Set("exclude", "*.txt")
	_ = command.Flags().Set("apply", "true")
	_ = command.Flags().Set("no-config-discovery", "true")

	options, err := parseSanitizeOptions(command)
	if err != nil {
		t.Fatalf("read sanitize options: %v", err)
	}

	if options.configFile != "custom.yaml" || !options.apply || !options.noConfigDiscovery {
		t.Fatalf("unexpected options: %#v", options)
	}
	if !options.includeSet || !options.excludeSet {
		t.Fatalf("expected include/exclude set flags, got %#v", options)
	}
}

func Test_Cmd_RunSanitize_ReturnsErrorForInvalidOptions(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")
	_ = command.Flags().Set("include", "invalid[")

	err := runSanitize(command, []string{"."})
	if err == nil {
		t.Fatal("expected runSanitize to return invalid include error")
	}
	if !strings.Contains(err.Error(), "read sanitize options") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_Cmd_RunSanitize_ReturnsNilOnValidInput(t *testing.T) {
	workingDir := t.TempDir()
	prompt := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(prompt, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")
	_ = command.Flags().Set("no-config-discovery", "true")

	if err := runSanitize(command, []string{workingDir}); err != nil {
		t.Fatalf("expected runSanitize to succeed, got %v", err)
	}
}
