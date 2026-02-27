package cmd

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/stretchr/testify/assert"
)

func Test_Cmd_ResolveEffectiveFilters_UsesConfigFiltersWhenCLIFlagsUnset(t *testing.T) {
	cfg := &config.Config{
		Filters: config.Filters{
			Include: []string{"*.md"},
			Exclude: []string{"*.yaml"},
		},
	}

	includes, excludes := resolveEffectiveFilters(cfg, nil, nil, false, false)

	assert.Equal(t, []string{"*.md"}, includes)
	assert.Equal(t, []string{"*.yaml"}, excludes)
}

func Test_Cmd_ResolveEffectiveFilters_OverridesOnlyIncludeWhenCLIIncludeSet(t *testing.T) {
	cfg := &config.Config{
		Filters: config.Filters{
			Include: []string{"*.md"},
			Exclude: []string{"*.yaml"},
		},
	}

	includes, excludes := resolveEffectiveFilters(cfg, []string{"*.txt"}, nil, true, false)

	assert.Equal(t, []string{"*.txt"}, includes)
	assert.Equal(t, []string{"*.yaml"}, excludes)
}

func Test_Cmd_ResolveEffectiveFilters_OverridesOnlyExcludeWhenCLIExcludeSet(t *testing.T) {
	cfg := &config.Config{
		Filters: config.Filters{
			Include: []string{"*.md"},
			Exclude: []string{"*.yaml"},
		},
	}

	includes, excludes := resolveEffectiveFilters(cfg, nil, []string{"*.tmp"}, false, true)

	assert.Equal(t, []string{"*.md"}, includes)
	assert.Equal(t, []string{"*.tmp"}, excludes)
}

func Test_Cmd_ResolveEffectiveFilters_AllowsCLIToClearConfigFilters(t *testing.T) {
	cfg := &config.Config{
		Filters: config.Filters{
			Include: []string{"*.md"},
			Exclude: []string{"*.yaml"},
		},
	}

	includes, excludes := resolveEffectiveFilters(cfg, []string{}, []string{}, true, true)

	assert.Empty(t, includes)
	assert.Empty(t, excludes)
}

func Test_Cmd_ResolveEffectiveFilters_UsesEmptyDefaultsWithoutConfig(t *testing.T) {
	includes, excludes := resolveEffectiveFilters(nil, nil, nil, false, false)

	assert.Empty(t, includes)
	assert.Empty(t, excludes)
}
