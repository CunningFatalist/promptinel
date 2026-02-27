package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/CunningFatalist/promptinel/internal/report"
	internalscan "github.com/CunningFatalist/promptinel/internal/scan"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	configFile        string
	noConfigDiscovery bool
	includes          []string
	excludes          []string
	includeSet        bool
	excludeSet        bool
	baselineFile      string
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
	options, err := parseScanOptions(cmd)
	if err != nil {
		return fmt.Errorf("read scan options: %w", err)
	}

	return runScanWithOptions(cmd.Context(), args, options)
}

func parseScanOptions(cmd *cobra.Command) (scanOptions, error) {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read config flag: %w", err)
	}
	noConfigDiscovery, err := cmd.Flags().GetBool("no-config-discovery")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read no-config-discovery flag: %w", err)
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

	if err := filters.ValidateGlobPatterns("include", includes); err != nil {
		return scanOptions{}, err
	}
	if err := filters.ValidateGlobPatterns("exclude", excludes); err != nil {
		return scanOptions{}, err
	}

	return scanOptions{
		configFile:        configFile,
		noConfigDiscovery: noConfigDiscovery,
		includes:          includes,
		excludes:          excludes,
		includeSet:        cmd.Flags().Changed("include"),
		excludeSet:        cmd.Flags().Changed("exclude"),
		baselineFile:      baselineFile,
	}, nil
}

func buildScanRequest(args []string, options scanOptions) internalscan.Request {
	return internalscan.Request{
		Paths:      args,
		ConfigFile: options.configFile,
		Discover:   !options.noConfigDiscovery,
		Include:    options.includes,
		Exclude:    options.excludes,
		IncludeSet: options.includeSet,
		ExcludeSet: options.excludeSet,
	}
}

func runScanWithOptions(ctx context.Context, args []string, options scanOptions) error {
	result, err := internalscan.Run(ctx, buildScanRequest(args, options))
	if err != nil {
		return err
	}

	findings := result.Findings
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

	code := exitcode.Resolve(result.Config.Policy, findings)
	if err := report.WriteScanText(os.Stdout, report.ScanSummary{
		Findings:         findings,
		Environment:      result.Config.Environment,
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

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().String("config", "", "Path to a Promptinel config file")
	scanCmd.Flags().Bool("no-config-discovery", false, "Disable implicit .promptinel.yaml discovery from current directory and $HOME")
	scanCmd.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	scanCmd.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
	scanCmd.Flags().String("baseline", "", "Path to baseline snapshot file used to suppress accepted findings")
}
