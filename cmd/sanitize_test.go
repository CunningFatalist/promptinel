package cmd

import (
	"context"
	"errors"
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

func Test_Cmd_BuildSanitizeRequest_MapsOptions(t *testing.T) {
	req := buildSanitizeRequest([]string{"."}, sanitizeOptions{
		configFile:        "custom.yaml",
		noConfigDiscovery: true,
		includes:          []string{"*.md"},
		excludes:          []string{"*.txt"},
		includeSet:        true,
		excludeSet:        true,
		apply:             true,
	})

	if req.ConfigFile != "custom.yaml" || req.Discover {
		t.Fatalf("unexpected request: %#v", req)
	}
	if len(req.Paths) != 1 || req.Paths[0] != "." || !req.IncludeSet || !req.ExcludeSet || !req.Apply {
		t.Fatalf("unexpected request mappings: %#v", req)
	}
}

func Test_Cmd_RunSanitize_SucceedsAndWritesReport(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\nline2\u200b\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")

	output := captureStdout(t, func() {
		if err := runSanitize(command, []string{workingDir}); err != nil {
			t.Fatalf("run sanitize: %v", err)
		}
	})

	if !strings.Contains(output, "Summary: files=") {
		t.Fatalf("expected sanitize summary in output, got:\n%s", output)
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

func Test_Cmd_RunSanitize_UsesCommandContext(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command.SetContext(ctx)

	err := runSanitize(command, []string{workingDir})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
