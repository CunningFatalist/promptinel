package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/report"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	configFile   string
	includes     []string
	excludes     []string
	baselineFile string
}

type sharedScanOptions struct {
	configFile string
	includes   []string
	excludes   []string
}

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan [path ...]",
	Short: "Scan prompt files for unsafe instructions and policy violations",
	Long: `Scan prompt files for deterministic security findings before they are executed by an LLM or agent.

Examples:
  promptinel scan prompts/
  promptinel scan --config .promptinel.yaml prompts/
  promptinel scan --include "*.md" prompts/
  promptinel scan --exclude "*.yaml" prompts/`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("scan command failed", runScan(cmd, args))
	},
}

func runScan(cmd *cobra.Command, args []string) error {
	options, err := scanOptionsFromCommand(cmd)
	if err != nil {
		return fmt.Errorf("read scan options: %w", err)
	}
	return runScanWithOptions(args, options)
}

func scanOptionsFromCommand(cmd *cobra.Command) (scanOptions, error) {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read config flag: %w", err)
	}

	includes, err := cmd.Flags().GetStringArray("include")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read include flag: %w", err)
	}

	excludes, err := cmd.Flags().GetStringArray("exclude")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read exclude flag: %w", err)
	}
	baselineFile, err := cmd.Flags().GetString("baseline")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read baseline flag: %w", err)
	}

	if err := validateGlobPatterns("include", includes); err != nil {
		return scanOptions{}, err
	}
	if err := validateGlobPatterns("exclude", excludes); err != nil {
		return scanOptions{}, err
	}

	return scanOptions{
		configFile:   configFile,
		includes:     includes,
		excludes:     excludes,
		baselineFile: baselineFile,
	}, nil
}

func validateGlobPatterns(flagName string, patterns []string) error {
	for i, pattern := range patterns {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid %s pattern at index %d (%q): %w", flagName, i, pattern, err)
		}
	}
	return nil
}

func runScanWithOptions(args []string, options scanOptions) error {
	findings, cfg, err := runSharedScan(args, sharedScanOptions{
		configFile: options.configFile,
		includes:   options.includes,
		excludes:   options.excludes,
	})
	if err != nil {
		return err
	}

	baselineFiltered := 0
	if options.baselineFile != "" {
		snapshot, baselineErr := baseline.Read(options.baselineFile)
		if baselineErr != nil {
			return fmt.Errorf("load baseline: %w", baselineErr)
		}
		filtered := baseline.FilterFindings(findings, snapshot)
		baselineFiltered = len(findings) - len(filtered)
		findings = filtered
	}

	code := exitcode.Resolve(cfg.Policy, findings)
	if err := report.WriteScanText(os.Stdout, report.ScanSummary{
		Findings:         findings,
		Environment:      cfg.Environment,
		BaselineFiltered: baselineFiltered,
		PolicyOutcome:    code,
	}); err != nil {
		return fmt.Errorf("write scan report: %w", err)
	}

	if code != exitcode.CodePass {
		return exitcode.Error{Code: code}
	}
	return nil
}

func runSharedScan(args []string, options sharedScanOptions) ([]engine.FileFinding, *config.Config, error) {
	cfg, err := config.Load(options.configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	registry, err := builtin.NewRegistry()
	if err != nil {
		return nil, nil, fmt.Errorf("initialize rule registry: %w", err)
	}

	compiledRules, err := registry.Compile(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("compile rules: %w", err)
	}

	scanner := engine.NewScanner(compiledRules, cfg)
	findings, err := scanner.ScanPaths(context.Background(), args, options.includes, options.excludes)
	if err != nil {
		return nil, nil, fmt.Errorf("scan files: %w", err)
	}

	findings = filterFindingsByMinimumSeverity(findings, cfg.Policy.WarnOn)

	return findings, cfg, nil
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

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().String("config", "", "Path to a Promptinel config file")
	scanCmd.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	scanCmd.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
	scanCmd.Flags().String("baseline", "", "Path to baseline snapshot file used to suppress accepted findings")
}
