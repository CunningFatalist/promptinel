package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type sarifPayload struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID     string                `json:"ruleId"`
	Level      string                `json:"level"`
	Locations  []sarifLocation       `json:"locations"`
	Properties sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	Category string `json:"category"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func Test_E2E_ScanSARIF_OutputIsValidAndDeterministic(t *testing.T) {
	repoRoot, err := repositoryRoot()
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

	first, firstExitCode := runScanSARIF(t, repoRoot)
	second, secondExitCode := runScanSARIF(t, repoRoot)

	if firstExitCode != secondExitCode {
		t.Fatalf("expected identical exit codes between runs, got %d and %d", firstExitCode, secondExitCode)
	}
	if firstExitCode != 1 {
		t.Fatalf("expected go run to exit with code 1 for non-zero command status, got %d", firstExitCode)
	}
	if first != second {
		t.Fatalf("expected deterministic SARIF output across runs")
	}

	var payload sarifPayload
	if err := json.Unmarshal([]byte(first), &payload); err != nil {
		t.Fatalf("unmarshal sarif payload: %v\noutput:\n%s", err, first)
	}

	if payload.Version != "2.1.0" {
		t.Fatalf("unexpected sarif version: %q", payload.Version)
	}
	if payload.Schema != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Fatalf("unexpected sarif schema: %q", payload.Schema)
	}
	if len(payload.Runs) != 1 {
		t.Fatalf("expected exactly one run, got %d", len(payload.Runs))
	}

	run := payload.Runs[0]
	if run.Tool.Driver.Name != "promptinel" {
		t.Fatalf("unexpected sarif driver name: %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected two SARIF results, got %d", len(run.Results))
	}

	uris := make([]string, 0, len(run.Results))
	for _, result := range run.Results {
		if result.RuleID != "no-zero-width" {
			t.Fatalf("unexpected result rule ID: %q", result.RuleID)
		}
		if result.Level != "error" {
			t.Fatalf("unexpected result level: %q", result.Level)
		}
		if result.Properties.Category != "finding" {
			t.Fatalf("unexpected result category: %q", result.Properties.Category)
		}
		if len(result.Locations) == 0 {
			t.Fatal("expected at least one location per result")
		}
		uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if !strings.HasPrefix(uri, "e2e/testdata/cases/") {
			t.Fatalf("unexpected artifact URI: %q", uri)
		}
		uris = append(uris, uri)
	}

	sort.Strings(uris)
	expectedURIs := []string{"e2e/testdata/cases/a-unsafe.md", "e2e/testdata/cases/b-unsafe.md"}
	for i := range expectedURIs {
		if uris[i] != expectedURIs[i] {
			t.Fatalf("unexpected artifact URI at index %d: got %q, want %q", i, uris[i], expectedURIs[i])
		}
	}
}

func runScanSARIF(t *testing.T, repoRoot string) (string, int) {
	t.Helper()

	cmd := exec.Command(
		"go",
		"run",
		"main.go",
		"scan",
		"--config",
		"e2e/testdata/promptinel.yaml",
		"--no-config-discovery",
		"--output",
		"sarif",
		"e2e/testdata/cases",
	)
	cmd.Dir = repoRoot

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err == nil {
		return stdout.String(), 0
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run scan command: %v", err)
	}

	if !strings.Contains(stderr.String(), "exit status 2") {
		t.Fatalf("expected stderr to mention promptinel fail code, got:\n%s", stderr.String())
	}

	return stdout.String(), exitErr.ExitCode()
}

func repositoryRoot() (string, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(workingDir, "..")), nil
}
