package scan

import (
	"context"
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
)

// Request configures a scan execution.
type Request struct {
	Paths      []string
	ConfigFile string
	Discover   bool
	Include    []string
	Exclude    []string
	IncludeSet bool
	ExcludeSet bool
}

// Result contains findings and effective configuration.
type Result struct {
	Findings []engine.FileFinding
	Config   *config.Config
}

// Run executes the shared scan workflow used by scan and baseline commands.
func Run(ctx context.Context, req Request) (Result, error) {
	cfg, err := config.LoadWithOptions(req.ConfigFile, config.LoadOptions{Discover: req.Discover})
	if err != nil {
		return Result{}, fmt.Errorf("load config: %w", err)
	}

	registry, err := builtin.NewRegistry()
	if err != nil {
		return Result{}, fmt.Errorf("initialize rule registry: %w", err)
	}

	compiledRules, err := registry.Compile(cfg)
	if err != nil {
		return Result{}, fmt.Errorf("compile rules: %w", err)
	}

	scanner := engine.NewScanner(compiledRules, cfg)
	includes, excludes := filters.ResolveEffective(cfg, req.Include, req.Exclude, req.IncludeSet, req.ExcludeSet)
	findings, err := scanner.ScanPaths(ctx, req.Paths, includes, excludes)
	if err != nil {
		return Result{}, fmt.Errorf("scan files: %w", err)
	}

	return Result{
		Findings: filterFindingsByMinimumSeverity(findings, cfg.Policy.WarnOn),
		Config:   cfg,
	}, nil
}

func filterFindingsByMinimumSeverity(findings []engine.FileFinding, minSeverity config.Severity) []engine.FileFinding {
	filtered := make([]engine.FileFinding, 0, len(findings))
	for _, finding := range findings {
		if config.SeverityAtLeast(finding.Severity, minSeverity) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}
