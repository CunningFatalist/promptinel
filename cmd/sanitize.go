package cmd

import (
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/report"
	internalsanitize "github.com/CunningFatalist/promptinel/internal/sanitize"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

type sanitizeOptions struct {
	configFile        string
	noConfigDiscovery bool
	includes          []string
	excludes          []string
	includeSet        bool
	excludeSet        bool
	apply             bool
}

// sanitizeCmd represents the sanitize command.
var sanitizeCmd = &cobra.Command{
	Use:   "sanitize [path ...]",
	Short: "Sanitize prompt files with safe, deterministic transformations",
	Long: `Sanitize prompt files using only safe transformations, such as removing invisible characters.

Examples:
  promptinel sanitize prompts/
  promptinel sanitize --apply prompts/
  promptinel sanitize --config .promptinel.yaml --apply prompts/
  promptinel sanitize --include "*.md" --apply prompts/
  promptinel sanitize --exclude "*.yaml" --apply prompts/`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("sanitize command failed", runSanitize(cmd, args))
	},
}

func runSanitize(cmd *cobra.Command, args []string) error {
	options, err := parseSanitizeOptions(cmd)
	if err != nil {
		return fmt.Errorf("read sanitize options: %w", err)
	}

	request := buildSanitizeRequest(args, options)
	result, err := internalsanitize.Run(cmd.Context(), request)
	if err != nil {
		return err
	}

	if err := report.WriteSanitizeText(os.Stdout, result); err != nil {
		return fmt.Errorf("write sanitize report: %w", err)
	}
	return nil
}

func parseSanitizeOptions(cmd *cobra.Command) (sanitizeOptions, error) {
	common, err := readConfigAndFilterFlags(cmd)
	if err != nil {
		return sanitizeOptions{}, err
	}
	apply, err := cmd.Flags().GetBool("apply")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read apply flag: %w", err)
	}

	return sanitizeOptions{
		configFile:        common.configFile,
		noConfigDiscovery: common.noConfigDiscovery,
		includes:          common.includes,
		excludes:          common.excludes,
		includeSet:        common.includeSet,
		excludeSet:        common.excludeSet,
		apply:             apply,
	}, nil
}

func buildSanitizeRequest(args []string, options sanitizeOptions) internalsanitize.Request {
	return internalsanitize.Request{
		Paths:      args,
		ConfigFile: options.configFile,
		Discover:   !options.noConfigDiscovery,
		Include:    options.includes,
		Exclude:    options.excludes,
		IncludeSet: options.includeSet,
		ExcludeSet: options.excludeSet,
		Apply:      options.apply,
	}
}

func init() {
	rootCmd.AddCommand(sanitizeCmd)
	addConfigAndFilterFlags(sanitizeCmd)
	sanitizeCmd.Flags().Bool("apply", false, "Apply sanitized output to files (default is dry-run preview)")
}
