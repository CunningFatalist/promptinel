package cmd

import (
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/filters"
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
	result, err := internalsanitize.Run(request)
	if err != nil {
		return err
	}

	if err := report.WriteSanitizeText(os.Stdout, result); err != nil {
		return fmt.Errorf("write sanitize report: %w", err)
	}
	return nil
}

func parseSanitizeOptions(cmd *cobra.Command) (sanitizeOptions, error) {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read config flag: %w", err)
	}
	noConfigDiscovery, err := cmd.Flags().GetBool("no-config-discovery")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read no-config-discovery flag: %w", err)
	}

	includes, err := cmd.Flags().GetStringArray("include")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read include flag: %w", err)
	}
	excludes, err := cmd.Flags().GetStringArray("exclude")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read exclude flag: %w", err)
	}
	apply, err := cmd.Flags().GetBool("apply")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read apply flag: %w", err)
	}

	if err := filters.ValidateGlobPatterns("include", includes); err != nil {
		return sanitizeOptions{}, err
	}
	if err := filters.ValidateGlobPatterns("exclude", excludes); err != nil {
		return sanitizeOptions{}, err
	}

	return sanitizeOptions{
		configFile:        configFile,
		noConfigDiscovery: noConfigDiscovery,
		includes:          includes,
		excludes:          excludes,
		includeSet:        cmd.Flags().Changed("include"),
		excludeSet:        cmd.Flags().Changed("exclude"),
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
	sanitizeCmd.Flags().String("config", "", "Path to a Promptinel config file")
	sanitizeCmd.Flags().Bool("no-config-discovery", false, "Disable implicit .promptinel.yaml discovery from current directory and $HOME")
	sanitizeCmd.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	sanitizeCmd.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
	sanitizeCmd.Flags().Bool("apply", false, "Apply sanitized output to files (default is dry-run preview)")
}
