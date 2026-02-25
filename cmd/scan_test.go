package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/rules"
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

func Test_Cmd_ScanOptionsFromCommand_ReadsFlagValues(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("baseline", "", "")

	if err := command.Flags().Set("config", "custom.yaml"); err != nil {
		t.Fatalf("set config flag: %v", err)
	}
	if err := command.Flags().Set("include", "*.md"); err != nil {
		t.Fatalf("set include flag: %v", err)
	}
	if err := command.Flags().Set("exclude", "*.txt"); err != nil {
		t.Fatalf("set exclude flag: %v", err)
	}
	if err := command.Flags().Set("baseline", "baseline.json"); err != nil {
		t.Fatalf("set baseline flag: %v", err)
	}
	if err := command.Flags().Set("no-config-discovery", "true"); err != nil {
		t.Fatalf("set no-config-discovery flag: %v", err)
	}

	options, err := scanOptionsFromCommand(command)
	if err != nil {
		t.Fatalf("read scan options: %v", err)
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
	if options.baselineFile != "baseline.json" {
		t.Fatalf("expected baseline file baseline.json, got %q", options.baselineFile)
	}
	if !options.noConfigDiscovery {
		t.Fatal("expected no-config-discovery to be true")
	}
}

func Test_Cmd_ScanOptionsFromCommand_ReturnsErrorForInvalidIncludeGlob(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("baseline", "", "")

	if err := command.Flags().Set("include", "invalid["); err != nil {
		t.Fatalf("set include flag: %v", err)
	}

	_, err := scanOptionsFromCommand(command)
	if err == nil {
		t.Fatal("expected include glob validation error")
	}
	if !strings.Contains(err.Error(), "invalid include pattern") {
		t.Fatalf("expected include validation error, got %v", err)
	}
}

func Test_Cmd_ScanOptionsFromCommand_ReturnsErrorForInvalidExcludeGlob(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().String("baseline", "", "")

	if err := command.Flags().Set("exclude", "invalid["); err != nil {
		t.Fatalf("set exclude flag: %v", err)
	}

	_, err := scanOptionsFromCommand(command)
	if err == nil {
		t.Fatal("expected exclude glob validation error")
	}
	if !strings.Contains(err.Error(), "invalid exclude pattern") {
		t.Fatalf("expected exclude validation error, got %v", err)
	}
}

func Test_Cmd_ScanCommand_FilterFindingsByMinimumSeverity_IgnoresLowerFindings(t *testing.T) {
	findings := []engine.FileFinding{
		{Finding: engineFindingWithSeverityForTest(config.SeverityLow)},
		{Finding: engineFindingWithSeverityForTest(config.SeverityMedium)},
		{Finding: engineFindingWithSeverityForTest(config.SeverityHigh)},
	}

	filtered := filterFindingsByMinimumSeverity(findings, config.SeverityMedium)

	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings after filtering, got %d", len(filtered))
	}
	if filtered[0].Severity != config.SeverityMedium {
		t.Fatalf("expected first finding to be medium, got %s", filtered[0].Severity)
	}
	if filtered[1].Severity != config.SeverityHigh {
		t.Fatalf("expected second finding to be high, got %s", filtered[1].Severity)
	}
}

func Test_Cmd_ScanCommand_FilterFindingsByMinimumSeverity_WithHighThreshold_OnlyKeepsHigh(t *testing.T) {
	findings := []engine.FileFinding{
		{Finding: engineFindingWithSeverityForTest(config.SeverityLow)},
		{Finding: engineFindingWithSeverityForTest(config.SeverityMedium)},
		{Finding: engineFindingWithSeverityForTest(config.SeverityHigh)},
	}

	filtered := filterFindingsByMinimumSeverity(findings, config.SeverityHigh)

	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filtering, got %d", len(filtered))
	}
	if filtered[0].Severity != config.SeverityHigh {
		t.Fatalf("expected high finding, got %s", filtered[0].Severity)
	}
}

func engineFindingWithSeverityForTest(severity config.Severity) rules.Finding {
	return rules.Finding{
		Severity: severity,
	}
}

func Test_Cmd_RunSharedScan_NoConfigDiscovery_IgnoresLocalConfig(t *testing.T) {
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
	filePath := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(filePath, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("change cwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})

	_, withDiscovery, err := runSharedScan([]string{"."}, sharedScanOptions{}, context.Background())
	if err != nil {
		t.Fatalf("run shared scan with discovery: %v", err)
	}
	_, withoutDiscovery, err := runSharedScan([]string{"."}, sharedScanOptions{noConfigDiscovery: true}, context.Background())
	if err != nil {
		t.Fatalf("run shared scan without discovery: %v", err)
	}

	if withDiscovery.Policy.WarnOn != config.SeverityLow {
		t.Fatalf("expected discovered config warn-on low, got %s", withDiscovery.Policy.WarnOn)
	}
	if withoutDiscovery.Policy.WarnOn != config.SeverityMedium {
		t.Fatalf("expected default warn-on medium without discovery, got %s", withoutDiscovery.Policy.WarnOn)
	}
}
