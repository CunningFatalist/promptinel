package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
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
	common, err := readConfigAndFilterFlags(cmd)
	if err != nil {
		return scanOptions{}, err
	}
	baselineFile, err := cmd.Flags().GetString("baseline")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read baseline flag: %w", err)
	}

	return scanOptions{
		configFile:        common.configFile,
		noConfigDiscovery: common.noConfigDiscovery,
		includes:          common.includes,
		excludes:          common.excludes,
		includeSet:        common.includeSet,
		excludeSet:        common.excludeSet,
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

	findings := result.ReportableFindings
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
	addConfigAndFilterFlags(scanCmd)
	scanCmd.Flags().String("baseline", "", "Path to baseline snapshot file used to suppress accepted findings")
}
