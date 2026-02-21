package cmd

import (
	"context"
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

type scanOptions struct {
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

	return scanOptions{
		configFile: configFile,
		includes:   includes,
		excludes:   excludes,
	}, nil
}

func runScanWithOptions(args []string, options scanOptions) error {
	cfg, err := config.Load(options.configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	registry, err := builtin.NewRegistry()
	if err != nil {
		return fmt.Errorf("initialize rule registry: %w", err)
	}

	compiledRules, err := registry.Compile(cfg)
	if err != nil {
		return fmt.Errorf("compile rules: %w", err)
	}

	scanner := engine.NewScanner(compiledRules, cfg)
	findings, err := scanner.ScanPaths(context.Background(), args, options.includes, options.excludes)
	if err != nil {
		return fmt.Errorf("scan files: %w", err)
	}

	for _, finding := range findings {
		fmt.Printf("%s:%d:%d [%s] %s: %s\n",
			finding.Path,
			finding.Position.Line,
			finding.Position.Column,
			finding.Severity,
			finding.ID,
			finding.Message,
		)
	}

	code := exitcode.Resolve(cfg.Policy, findings)
	if code != exitcode.CodePass {
		return exitcode.Error{Code: code}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().String("config", "", "Path to a Promptinel config file")
	scanCmd.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	scanCmd.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
}
