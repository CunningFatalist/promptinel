package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	internalscan "github.com/CunningFatalist/promptinel/internal/scan"
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

func Test_Cmd_RunScanWithOptions_ReportsOversizedSkipsAtDefaultWarnOn(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "limits:\n  max_file_size_bytes: 1\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	filePath := filepath.Join(workingDir, "big.md")
	if err := os.WriteFile(filePath, []byte("oversized content"), 0o644); err != nil {
		t.Fatalf("write oversized file: %v", err)
	}

	output := captureStdout(t, func() {
		err := runScanWithOptions(context.Background(), []string{filePath}, scanOptions{
			configFile:        configPath,
			noConfigDiscovery: true,
		})
		if err != nil {
			t.Fatalf("run scan with options: %v", err)
		}
	})

	if !strings.Contains(output, "Oversized Skips:") {
		t.Fatalf("expected oversized skip section, got output:\n%s", output)
	}
	if !strings.Contains(output, "scan-file-too-large") {
		t.Fatalf("expected oversized skip finding ID in output, got output:\n%s", output)
	}
	if !strings.Contains(output, "- policy: PASS") {
		t.Fatalf("expected oversized skip to remain informational, got output:\n%s", output)
	}
}

func Test_Cmd_RunScanWithOptions_ReturnsExitcodeErrorWhenPolicyThresholdReached(t *testing.T) {
	workingDir := t.TempDir()
	filePath := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(filePath, []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	var err error
	_ = captureStdout(t, func() {
		err = runScanWithOptions(context.Background(), []string{filePath}, scanOptions{
			noConfigDiscovery: true,
		})
	})
	if err == nil {
		t.Fatal("expected non-pass exit error")
	}

	var codeErr exitcode.Error
	if !errors.As(err, &codeErr) {
		t.Fatalf("expected exitcode.Error, got %T (%v)", err, err)
	}
	if codeErr.Code != exitcode.CodeFail {
		t.Fatalf("expected fail exit code, got %d", codeErr.Code)
	}
}

func Test_Cmd_RunScanWithOptions_ReturnsErrorWhenBaselineLoadFails(t *testing.T) {
	workingDir := t.TempDir()
	filePath := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(filePath, []byte("plain content"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	err := runScanWithOptions(context.Background(), []string{filePath}, scanOptions{
		noConfigDiscovery: true,
		baselineFile:      filepath.Join(workingDir, "missing-baseline.json"),
	})
	if err == nil {
		t.Fatal("expected baseline load error")
	}
	if !strings.Contains(err.Error(), "load baseline") {
		t.Fatalf("expected load baseline error, got %v", err)
	}
}

func Test_Cmd_RunScanWithOptions_ReturnsErrorWhenScanRunFails(t *testing.T) {
	err := runScanWithOptions(context.Background(), []string{filepath.Join(t.TempDir(), "missing.md")}, scanOptions{
		noConfigDiscovery: true,
	})
	if err == nil {
		t.Fatal("expected scan run error")
	}
	if !strings.Contains(err.Error(), "scan files") {
		t.Fatalf("expected scan files error, got %v", err)
	}
}

func Test_Cmd_RunScanWithOptions_AppliesBaselineAndStaysPass(t *testing.T) {
	workingDir := t.TempDir()
	filePath := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(filePath, []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	baselinePath := filepath.Join(workingDir, "baseline.json")
	initialResult, err := internalscan.Run(context.Background(), internalscan.Request{
		Paths:    []string{filePath},
		Discover: false,
	})
	if err != nil {
		t.Fatalf("run initial scan: %v", err)
	}
	if len(initialResult.ReportableFindings) == 0 {
		t.Fatal("expected reportable findings before applying baseline")
	}
	if err := baseline.Write(baselinePath, baseline.BuildSnapshot(initialResult.ReportableFindings)); err != nil {
		t.Fatalf("write baseline snapshot: %v", err)
	}

	output := captureStdout(t, func() {
		err := runScanWithOptions(context.Background(), []string{filePath}, scanOptions{
			noConfigDiscovery: true,
			baselineFile:      baselinePath,
		})
		if err != nil {
			t.Fatalf("run scan with baseline: %v", err)
		}
	})

	if !strings.Contains(output, "- filtered_by_baseline: 1") {
		t.Fatalf("expected baseline filtering summary, got output:\n%s", output)
	}
	if !strings.Contains(output, "- policy: PASS") {
		t.Fatalf("expected pass policy with filtered findings, got output:\n%s", output)
	}
}

func Test_Cmd_RunScanWithOptions_ReturnsErrorWhenReportWriteFails(t *testing.T) {
	workingDir := t.TempDir()
	filePath := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(filePath, []byte("plain content"), 0o644); err != nil {
		t.Fatalf("write prompt file: %v", err)
	}

	previousStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = previousStdout
		_ = reader.Close()
	}()

	err = runScanWithOptions(context.Background(), []string{filePath}, scanOptions{noConfigDiscovery: true})
	if err == nil {
		t.Fatal("expected write scan report error")
	}
	if !strings.Contains(err.Error(), "write scan report") {
		t.Fatalf("expected write scan report error, got %v", err)
	}
}
