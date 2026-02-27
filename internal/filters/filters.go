package filters

import (
	"fmt"
	"path/filepath"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/pathmatch"
)

// ValidateGlobPatterns ensures each provided glob pattern is syntactically valid.
func ValidateGlobPatterns(flagName string, patterns []string) error {
	for i, pattern := range patterns {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid %s pattern at index %d (%q): %w", flagName, i, pattern, err)
		}
	}
	return nil
}

// ResolveEffective merges CLI filters with config defaults.
// CLI values only override config when the corresponding flag was set.
func ResolveEffective(
	cfg *config.Config,
	cliInclude []string,
	cliExclude []string,
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
		includes = cliInclude
	}
	if excludeSet {
		excludes = cliExclude
	}

	return includes, excludes
}

// Match reports whether path matches include/exclude rules.
func Match(path string, includePatterns []string, excludePatterns []string) bool {
	included := len(includePatterns) == 0
	for _, include := range includePatterns {
		if matchPattern(include, path) {
			included = true
			break
		}
	}
	if !included {
		return false
	}

	for _, exclude := range excludePatterns {
		if matchPattern(exclude, path) {
			return false
		}
	}

	return true
}

func matchPattern(pattern string, path string) bool {
	if pathmatch.Match(pattern, path) {
		return true
	}
	if pathmatch.Match(pattern, filepath.Base(path)) {
		return true
	}
	return false
}
