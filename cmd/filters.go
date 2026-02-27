package cmd

import "github.com/CunningFatalist/promptinel/internal/config"

func resolveEffectiveFilters(
	cfg *config.Config,
	cliIncludes []string,
	cliExcludes []string,
	includeSet bool,
	excludeSet bool,
) ([]string, []string) {
	includes := []string{}
	excludes := []string{}

	if cfg != nil {
		includes = cfg.Filters.Include
		excludes = cfg.Filters.Exclude
	}

	if includeSet {
		includes = cliIncludes
	}
	if excludeSet {
		excludes = cliExcludes
	}

	return includes, excludes
}
