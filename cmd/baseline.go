package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/baseline"
	"github.com/CunningFatalist/promptinel/internal/report"
	internalscan "github.com/CunningFatalist/promptinel/internal/scan"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

type baselineOptions struct {
	configFile        string
	noConfigDiscovery bool
	includes          []string
	excludes          []string
	includeSet        bool
	excludeSet        bool
	file              string
}

// baselineCmd represents the baseline command.
var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Create and update baseline files for CI adoption",
	Long: `Manage baseline snapshots of existing findings to support gradual adoption in CI.

Examples:
  promptinel baseline create
  promptinel baseline update`,
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create [path ...]",
	Short: "Create a baseline snapshot from current findings",
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("baseline create command failed", runBaselineCreate(cmd, args))
	},
}

var baselineUpdateCmd = &cobra.Command{
	Use:   "update [path ...]",
	Short: "Update an existing baseline snapshot with current findings",
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("baseline update command failed", runBaselineUpdate(cmd, args))
	},
}

func runBaselineCreate(cmd *cobra.Command, args []string) error {
	options, err := parseBaselineOptions(cmd)
	if err != nil {
		return fmt.Errorf("read baseline create options: %w", err)
	}

	return runBaselineSnapshot(cmd.Context(), args, options, false)
}

func runBaselineUpdate(cmd *cobra.Command, args []string) error {
	options, err := parseBaselineOptions(cmd)
	if err != nil {
		return fmt.Errorf("read baseline update options: %w", err)
	}

	if _, err := os.Stat(options.file); err != nil {
		return fmt.Errorf("stat baseline file %q: %w", options.file, err)
	}

	return runBaselineSnapshot(cmd.Context(), args, options, true)
}

func parseBaselineOptions(cmd *cobra.Command) (baselineOptions, error) {
	common, err := readConfigAndFilterFlags(cmd)
	if err != nil {
		return baselineOptions{}, err
	}
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		return baselineOptions{}, fmt.Errorf("read file flag: %w", err)
	}

	return baselineOptions{
		configFile:        common.configFile,
		noConfigDiscovery: common.noConfigDiscovery,
		includes:          common.includes,
		excludes:          common.excludes,
		includeSet:        common.includeSet,
		excludeSet:        common.excludeSet,
		file:              file,
	}, nil
}

func buildBaselineScanRequest(args []string, options baselineOptions) internalscan.Request {
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	return internalscan.Request{
		Paths:      paths,
		ConfigFile: options.configFile,
		Discover:   !options.noConfigDiscovery,
		Include:    options.includes,
		Exclude:    options.excludes,
		IncludeSet: options.includeSet,
		ExcludeSet: options.excludeSet,
	}
}

func runBaselineSnapshot(ctx context.Context, args []string, options baselineOptions, update bool) error {
	result, err := internalscan.Run(ctx, buildBaselineScanRequest(args, options))
	if err != nil {
		return err
	}

	snapshot := baseline.BuildSnapshot(result.RawFindings)
	previousEntryCount := 0
	if update {
		previousSnapshot, readErr := baseline.Read(options.file)
		if readErr != nil {
			return fmt.Errorf("load existing baseline file %q: %w", options.file, readErr)
		}
		previousEntryCount = len(previousSnapshot.Entries)
	}

	if err := baseline.Write(options.file, snapshot); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}

	if err := report.WriteBaselineText(os.Stdout, report.BaselineSummary{
		File:            options.file,
		Entries:         len(snapshot.Entries),
		Updated:         update,
		PreviousEntries: previousEntryCount,
	}); err != nil {
		return fmt.Errorf("write baseline report: %w", err)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(baselineCmd)
	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineUpdateCmd)

	addConfigAndFilterFlags(baselineCreateCmd)
	baselineCreateCmd.Flags().String("file", baseline.DefaultFileName, "Path to write baseline snapshot file")

	addConfigAndFilterFlags(baselineUpdateCmd)
	baselineUpdateCmd.Flags().String("file", baseline.DefaultFileName, "Path to write baseline snapshot file")
}
