package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/spf13/cobra"
)

func Test_Cmd_ScanCommand_RequiresAtLeastOnePath(t *testing.T) {
	if err := scanCmd.Args(scanCmd, nil); err == nil {
		t.Fatal("expected error when no path arguments are provided")
	}
}

func Test_Cmd_ScanCommand_AcceptsPathArguments(t *testing.T) {
	if err := scanCmd.Args(scanCmd, []string{"prompts"}); err != nil {
		t.Fatalf("expected valid args, got error: %v", err)
	}
}

func Test_Cmd_ExitCodeError_ReturnsExpectedMessage(t *testing.T) {
	err := exitcode.Error{Code: exitcode.CodeFail}
	if err.Error() != "exit code 2" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func Test_Cmd_ParseScanOptions_ReadsFlagValues(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("baseline", "", "")

	_ = command.Flags().Set("config", "custom.yaml")
	_ = command.Flags().Set("include", "*.md")
	_ = command.Flags().Set("exclude", "*.txt")
	_ = command.Flags().Set("baseline", "baseline.json")
	_ = command.Flags().Set("no-config-discovery", "true")

	options, err := parseScanOptions(command)
	if err != nil {
		t.Fatalf("read scan options: %v", err)
	}

	if options.configFile != "custom.yaml" || options.baselineFile != "baseline.json" {
		t.Fatalf("unexpected options: %#v", options)
	}
	if !options.includeSet || !options.excludeSet || !options.noConfigDiscovery {
		t.Fatalf("unexpected flag state: %#v", options)
	}
}

func Test_Cmd_ParseScanOptions_ReturnsErrorForInvalidIncludeGlob(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("baseline", "", "")
	_ = command.Flags().Set("include", "invalid[")

	_, err := parseScanOptions(command)
	if err == nil {
		t.Fatal("expected include glob validation error")
	}
	if !strings.Contains(err.Error(), "invalid include pattern") {
		t.Fatalf("expected include validation error, got %v", err)
	}
}

func Test_Cmd_BuildScanRequest_MapsOptions(t *testing.T) {
	req := buildScanRequest([]string{"."}, scanOptions{
		configFile:        "custom.yaml",
		noConfigDiscovery: true,
		includes:          []string{"*.md"},
		excludes:          []string{"*.txt"},
		includeSet:        true,
		excludeSet:        true,
	})

	if req.ConfigFile != "custom.yaml" || req.Discover {
		t.Fatalf("unexpected request: %#v", req)
	}
	if len(req.Paths) != 1 || req.Paths[0] != "." || !req.IncludeSet || !req.ExcludeSet {
		t.Fatalf("unexpected request mappings: %#v", req)
	}
}

func Test_Cmd_RunScan_ReturnsErrorForInvalidOptions(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("baseline", "", "")
	_ = command.Flags().Set("include", "invalid[")

	err := runScan(command, []string{"."})
	if err == nil {
		t.Fatal("expected runScan to return invalid include error")
	}
	if !strings.Contains(err.Error(), "read scan options") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_Cmd_RunScanWithOptions_ReturnsNilOnCleanInput(t *testing.T) {
	workingDir := t.TempDir()
	prompt := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(prompt, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	err := runScanWithOptions(context.Background(), []string{workingDir}, scanOptions{noConfigDiscovery: true})
	if err != nil {
		t.Fatalf("expected clean scan to pass, got %v", err)
	}
}
