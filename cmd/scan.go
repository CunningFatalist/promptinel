package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

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
	output            scanOutputFormat
}

type scanOutputFormat string

const (
	scanOutputText  scanOutputFormat = "text"
	scanOutputJSON  scanOutputFormat = "json"
	scanOutputSARIF scanOutputFormat = "sarif"
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan [path ...]",
	Short: "Scan prompt files for unsafe instructions and policy violations",
	Long: `Scan prompt files for deterministic security findings before they are executed by an LLM or agent.

Examples:
  promptinel scan prompts/
  promptinel scan --config .promptinel.yaml prompts/
  promptinel scan --include "*.md" prompts/
  promptinel scan --exclude "*.yaml" prompts/
  promptinel scan --output sarif prompts/`,
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
	outputValue, err := cmd.Flags().GetString("output")
	if err != nil {
		return scanOptions{}, fmt.Errorf("read output flag: %w", err)
	}
	output, err := parseScanOutputFormat(outputValue)
	if err != nil {
		return scanOptions{}, err
	}

	return scanOptions{
		configFile:        common.configFile,
		noConfigDiscovery: common.noConfigDiscovery,
		includes:          common.includes,
		excludes:          common.excludes,
		includeSet:        common.includeSet,
		excludeSet:        common.excludeSet,
		baselineFile:      baselineFile,
		output:            output,
	}, nil
}

func parseScanOutputFormat(raw string) (scanOutputFormat, error) {
	switch scanOutputFormat(strings.ToLower(strings.TrimSpace(raw))) {
	case scanOutputText:
		return scanOutputText, nil
	case scanOutputJSON:
		return scanOutputJSON, nil
	case scanOutputSARIF:
		return scanOutputSARIF, nil
	default:
		return "", fmt.Errorf("invalid output format %q: expected one of text, json, sarif", raw)
	}
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
	summary := report.ScanSummary{
		Findings:         findings,
		OversizedSkipped: result.OversizedSkippedFindings,
		Environment:      result.Config.Environment,
		BaselineFiltered: baselineFiltered,
		PolicyOutcome:    code,
	}

	var writeErr error
	switch options.output {
	case scanOutputJSON:
		writeErr = report.WriteScanJSON(os.Stdout, summary)
	case scanOutputSARIF:
		writeErr = report.WriteScanSARIF(os.Stdout, summary)
	default:
		writeErr = report.WriteScanText(os.Stdout, summary)
	}

	if writeErr != nil {
		return fmt.Errorf("write scan report: %w", writeErr)
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
	scanCmd.Flags().String("output", string(scanOutputText), "Output format: text, json, sarif")
}
