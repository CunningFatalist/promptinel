package scan

import (
	"context"
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/CunningFatalist/promptinel/internal/finding"
	"github.com/CunningFatalist/promptinel/internal/rulecatalog"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

// Request configures a scan execution.
type Request struct {
	Paths           []string
	ConfigFile      string
	Discover        bool
	Include         []string
	Exclude         []string
	IncludeSet      bool
	ExcludeSet      bool
	RegistryFactory RegistryFactory
}

// RegistryFactory creates a rule registry for one scan execution.
type RegistryFactory func() (*rules.Registry, error)

// Result contains findings and effective configuration.
type Result struct {
	// Findings contains reportable findings after policy warn-on filtering.
	// This field is kept for compatibility; prefer ReportableFindings.
	Findings []finding.FileFinding
	// ReportableFindings contains findings after policy warn-on filtering.
	ReportableFindings []finding.FileFinding
	// RawFindings contains all findings before policy warn-on filtering.
	RawFindings []finding.FileFinding
	// OversizedSkippedFindings contains diagnostics for files skipped because
	// they exceeded limits.max_file_size_bytes. These are always surfaced in scan output
	// and remain informational (they do not affect policy exit code).
	OversizedSkippedFindings []finding.FileFinding
	// UnreadableSkippedFindings contains diagnostics for files skipped because
	// they could not be safely opened or read. These are always surfaced in scan output
	// and remain informational (they do not affect policy exit code).
	UnreadableSkippedFindings []finding.FileFinding
	RuleDocs                  map[string]string
	Config                    *config.Config
}

// Run executes the shared scan workflow used by scan and baseline commands.
func Run(ctx context.Context, req Request) (Result, error) {
	cfg, err := config.LoadWithOptions(req.ConfigFile, config.LoadOptions{Discover: req.Discover})
	if err != nil {
		return Result{}, fmt.Errorf("load config: %w", err)
	}

	if req.RegistryFactory == nil {
		return Result{}, fmt.Errorf("initialize rule registry: missing registry factory")
	}

	registry, err := req.RegistryFactory()
	if err != nil {
		return Result{}, fmt.Errorf("initialize rule registry: %w", err)
	}

	compiledRules, err := registry.Compile(cfg)
	if err != nil {
		return Result{}, fmt.Errorf("compile rules: %w", err)
	}

	scanner := engine.NewScanner(compiledRules, cfg)
	includes, excludes := filters.ResolveEffective(cfg, req.Include, req.Exclude, req.IncludeSet, req.ExcludeSet)
	rawFindings, err := scanner.ScanPaths(ctx, req.Paths, includes, excludes)
	if err != nil {
		return Result{}, fmt.Errorf("scan files: %w", err)
	}
	reportableFindings := filterFindingsByMinimumSeverity(rawFindings, cfg.Policy.WarnOn)
	oversizedSkippedFindings := filterOversizedSkippedFindings(rawFindings)
	unreadableSkippedFindings := filterUnreadableSkippedFindings(rawFindings)

	return Result{
		Findings:                  reportableFindings,
		ReportableFindings:        reportableFindings,
		RawFindings:               rawFindings,
		OversizedSkippedFindings:  oversizedSkippedFindings,
		UnreadableSkippedFindings: unreadableSkippedFindings,
		RuleDocs:                  rulecatalog.DocsURLIndex(registry, cfg.CustomRules),
		Config:                    cfg,
	}, nil
}

func filterFindingsByMinimumSeverity(findings []finding.FileFinding, minSeverity config.Severity) []finding.FileFinding {
	filtered := make([]finding.FileFinding, 0, len(findings))
	for _, item := range findings {
		if finding.IsOversizedFileSkip(item) || finding.IsUnreadableFileSkip(item) {
			continue
		}
		if config.SeverityAtLeast(item.Severity, minSeverity) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterOversizedSkippedFindings(findings []finding.FileFinding) []finding.FileFinding {
	filtered := make([]finding.FileFinding, 0, len(findings))
	for _, item := range findings {
		if finding.IsOversizedFileSkip(item) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterUnreadableSkippedFindings(findings []finding.FileFinding) []finding.FileFinding {
	filtered := make([]finding.FileFinding, 0, len(findings))
	for _, item := range findings {
		if finding.IsUnreadableFileSkip(item) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
