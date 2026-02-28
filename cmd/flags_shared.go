package cmd

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/spf13/cobra"
)

type configFilterOptions struct {
	configFile        string
	noConfigDiscovery bool
	includes          []string
	excludes          []string
	includeSet        bool
	excludeSet        bool
}

func addConfigAndFilterFlags(command *cobra.Command) {
	command.Flags().String("config", "", "Path to a Promptinel config file")
	command.Flags().Bool("no-config-discovery", false, "Disable implicit .promptinel.yaml discovery from current directory and $HOME")
	command.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	command.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
}

func readConfigAndFilterFlags(cmd *cobra.Command) (configFilterOptions, error) {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return configFilterOptions{}, fmt.Errorf("read config flag: %w", err)
	}
	noConfigDiscovery, err := cmd.Flags().GetBool("no-config-discovery")
	if err != nil {
		return configFilterOptions{}, fmt.Errorf("read no-config-discovery flag: %w", err)
	}

	includes, err := cmd.Flags().GetStringArray("include")
	if err != nil {
		return configFilterOptions{}, fmt.Errorf("read include flag: %w", err)
	}
	excludes, err := cmd.Flags().GetStringArray("exclude")
	if err != nil {
		return configFilterOptions{}, fmt.Errorf("read exclude flag: %w", err)
	}

	if err := filters.ValidateGlobPatterns("include", includes); err != nil {
		return configFilterOptions{}, err
	}
	if err := filters.ValidateGlobPatterns("exclude", excludes); err != nil {
		return configFilterOptions{}, err
	}

	return configFilterOptions{
		configFile:        configFile,
		noConfigDiscovery: noConfigDiscovery,
		includes:          includes,
		excludes:          excludes,
		includeSet:        cmd.Flags().Changed("include"),
		excludeSet:        cmd.Flags().Changed("exclude"),
	}, nil
}
