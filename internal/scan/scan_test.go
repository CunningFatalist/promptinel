package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
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

	withDiscovery, err := Run(context.Background(), Request{Paths: []string{"."}, Discover: true})
	if err != nil {
		t.Fatalf("run shared scan with discovery: %v", err)
	}
	withoutDiscovery, err := Run(context.Background(), Request{Paths: []string{"."}, Discover: false})
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
		Paths:      []string{workingDir},
		ConfigFile: configPath,
		Discover:   false,
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
		Paths:      []string{workingDir},
		ConfigFile: configPath,
		Discover:   false,
		Include:    []string{"*.txt"},
		IncludeSet: true,
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
