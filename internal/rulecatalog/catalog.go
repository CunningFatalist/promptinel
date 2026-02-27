package rulecatalog

import (
	"fmt"
	"sort"

	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
)

// List returns all built-in rule metadata sorted by rule id.
func List() ([]rules.Metadata, error) {
	registry, err := builtin.NewRegistry()
	if err != nil {
		return nil, fmt.Errorf("initialize rule registry: %w", err)
	}

	ruleSet := registry.List()
	sort.SliceStable(ruleSet, func(i, j int) bool {
		return ruleSet[i].ID < ruleSet[j].ID
	})
	return ruleSet, nil
}

// Describe returns metadata for a single built-in rule by id.
func Describe(id string) (rules.Metadata, bool, error) {
	registry, err := builtin.NewRegistry()
	if err != nil {
		return rules.Metadata{}, false, fmt.Errorf("initialize rule registry: %w", err)
	}

	meta, exists := registry.Describe(id)
	return meta, exists, nil
}
