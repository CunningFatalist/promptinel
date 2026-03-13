package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
	internalsanitize "github.com/CunningFatalist/promptinel/internal/sanitize"
)

func Test_Scan_Run_NoConfigDiscovery_IgnoresLocalConfig(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "policy:\n  fail-on: low\n  warn-on: low\n"
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
	t.Cleanup(func() { _ = os.Chdir(previousWD) })

	withDiscovery, err := Run(context.Background(), Request{
		Paths:           []string{"."},
		Discover:        true,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run shared scan with discovery: %v", err)
	}
	withoutDiscovery, err := Run(context.Background(), Request{
		Paths:           []string{"."},
		Discover:        false,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run shared scan without discovery: %v", err)
	}

	if withDiscovery.Config.Policy.WarnOn != config.SeverityLow {
		t.Fatalf("expected discovered config warn-on low, got %s", withDiscovery.Config.Policy.WarnOn)
	}
	if withoutDiscovery.Config.Policy.WarnOn != config.SeverityMedium {
		t.Fatalf("expected default warn-on medium without discovery, got %s", withoutDiscovery.Config.Policy.WarnOn)
	}
}

func Test_Scan_Run_ReturnsErrorWhenRegistryFactoryMissing(t *testing.T) {
	_, err := Run(context.Background(), Request{
		Paths:    []string{"."},
		Discover: false,
	})
	if err == nil {
		t.Fatal("expected missing registry factory error")
	}
	if !strings.Contains(err.Error(), "missing registry factory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_Scan_Run_ConfigFiltersApplyWhenCLIFlagsUnset(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "filters:\n  include:\n    - \"*.md\"\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "included.md"), []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write markdown file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "excluded.txt"), []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write txt file: %v", err)
	}

	result, err := Run(context.Background(), Request{
		Paths:           []string{workingDir},
		ConfigFile:      configPath,
		Discover:        false,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run shared scan: %v", err)
	}

	for _, finding := range result.Findings {
		if strings.HasSuffix(finding.Path, "excluded.txt") {
			t.Fatalf("expected config include filter to skip excluded.txt, findings: %#v", result.Findings)
		}
	}
}

func Test_Scan_Run_CLIIncludeOverridesConfigFilters(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "filters:\n  include:\n    - \"*.md\"\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "excluded-by-cli.md"), []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write markdown file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "included-by-cli.txt"), []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write txt file: %v", err)
	}

	result, err := Run(context.Background(), Request{
		Paths:           []string{workingDir},
		ConfigFile:      configPath,
		Discover:        false,
		Include:         []string{"*.txt"},
		IncludeSet:      true,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run shared scan: %v", err)
	}

	for _, finding := range result.Findings {
		if strings.HasSuffix(finding.Path, "excluded-by-cli.md") {
			t.Fatalf("expected CLI include filter to override config include filter, findings: %#v", result.Findings)
		}
	}
}

func Test_Scan_Run_ReturnsRawAndReportableFindingsSeparately(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	link := filepath.Join(workingDir, "broken.md")
	if err := os.Symlink(filepath.Join(workingDir, "missing.md"), link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	result, err := Run(context.Background(), Request{
		Paths:           []string{link},
		Discover:        false,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}

	if len(result.RawFindings) != 1 {
		t.Fatalf("expected one raw finding, got %#v", result.RawFindings)
	}
	if len(result.ReportableFindings) != 0 {
		t.Fatalf("expected no reportable findings at default warn-on=medium, got %#v", result.ReportableFindings)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected compatibility findings to match reportable findings, got %#v", result.Findings)
	}
	if len(result.UnreadableSkippedFindings) != 1 {
		t.Fatalf("expected one unreadable skip finding, got %#v", result.UnreadableSkippedFindings)
	}
}

func Test_Scan_Run_OversizedSkipsRemainInformationalAndVisible(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := "policy:\n  fail-on: low\n  warn-on: low\nlimits:\n  max_file_size_bytes: 1\n"
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	filePath := filepath.Join(workingDir, "big.md")
	if err := os.WriteFile(filePath, []byte("this file is larger than one byte"), 0o644); err != nil {
		t.Fatalf("write oversized file: %v", err)
	}

	result, err := Run(context.Background(), Request{
		Paths:           []string{filePath},
		ConfigFile:      configPath,
		Discover:        false,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}

	if len(result.RawFindings) != 1 {
		t.Fatalf("expected one raw finding, got %#v", result.RawFindings)
	}
	if len(result.ReportableFindings) != 0 {
		t.Fatalf("expected oversized skip to stay informational and excluded from reportable findings, got %#v", result.ReportableFindings)
	}
	if len(result.OversizedSkippedFindings) != 1 {
		t.Fatalf("expected one oversized skip finding, got %#v", result.OversizedSkippedFindings)
	}
	if len(result.UnreadableSkippedFindings) != 0 {
		t.Fatalf("expected no unreadable skip findings, got %#v", result.UnreadableSkippedFindings)
	}
}

func Test_Scan_Run_FileTargetingMatchesSanitizeForEquivalentPatterns(t *testing.T) {
	workingDir := t.TempDir()
	include := []string{"*.md"}

	markdownFile := filepath.Join(workingDir, "target.md")
	if err := os.WriteFile(markdownFile, []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write markdown file: %v", err)
	}
	textFile := filepath.Join(workingDir, "excluded.txt")
	if err := os.WriteFile(textFile, []byte("hello\u200bworld"), 0o644); err != nil {
		t.Fatalf("write text file: %v", err)
	}

	expectedScanBasenames := []string{"target.md"}
	if runtime.GOOS != "windows" {
		link := filepath.Join(workingDir, "broken.md")
		if err := os.Symlink(filepath.Join(workingDir, "missing.md"), link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		expectedScanBasenames = append(expectedScanBasenames, "broken.md")
	}

	scanResult, err := Run(context.Background(), Request{
		Paths:           []string{workingDir},
		Discover:        false,
		Include:         include,
		IncludeSet:      true,
		RegistryFactory: builtin.NewRegistry,
	})
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}

	sanitizeResult, err := internalsanitize.Run(context.Background(), internalsanitize.Request{
		Paths:      []string{workingDir},
		Discover:   false,
		Include:    include,
		IncludeSet: true,
	})
	if err != nil {
		t.Fatalf("run sanitize: %v", err)
	}

	scanBasenames := findingBasenames(scanResult.RawFindings)
	sanitizeBasenames := sanitizeEventBasenames(sanitizeResult.Events)
	sort.Strings(expectedScanBasenames)

	if strings.Join(scanBasenames, ",") != strings.Join(expectedScanBasenames, ",") {
		t.Fatalf("unexpected scan targets: got=%v want=%v", scanBasenames, expectedScanBasenames)
	}
	if strings.Join(sanitizeBasenames, ",") != strings.Join(expectedScanBasenames, ",") {
		t.Fatalf("unexpected sanitize targets: got=%v want=%v", sanitizeBasenames, expectedScanBasenames)
	}
}

func findingBasenames(findings []engine.FileFinding) []string {
	seen := make(map[string]struct{})
	for _, finding := range findings {
		seen[filepath.Base(finding.Path)] = struct{}{}
	}

	basenames := make([]string, 0, len(seen))
	for name := range seen {
		basenames = append(basenames, name)
	}
	sort.Strings(basenames)
	return basenames
}

func sanitizeEventBasenames(events []internalsanitize.Event) []string {
	seen := make(map[string]struct{})
	for _, event := range events {
		seen[filepath.Base(event.Path)] = struct{}{}
	}

	basenames := make([]string, 0, len(seen))
	for name := range seen {
		basenames = append(basenames, name)
	}
	sort.Strings(basenames)
	return basenames
}
