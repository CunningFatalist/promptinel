package rulecatalog

import (
	"fmt"
	"sort"

	"github.com/CunningFatalist/promptinel/internal/rules"
)

// RegistryFactory creates a rule registry for catalog operations.
type RegistryFactory func() (*rules.Registry, error)

// List returns all built-in rule metadata sorted by rule id.
func List(registryFactory RegistryFactory) ([]rules.Metadata, error) {
	if registryFactory == nil {
		return nil, fmt.Errorf("initialize rule registry: missing registry factory")
	}

	registry, err := registryFactory()
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
func Describe(registryFactory RegistryFactory, id string) (rules.Metadata, bool, error) {
	if registryFactory == nil {
		return rules.Metadata{}, false, fmt.Errorf("initialize rule registry: missing registry factory")
	}

	registry, err := registryFactory()
	if err != nil {
		return rules.Metadata{}, false, fmt.Errorf("initialize rule registry: %w", err)
	}

	meta, exists := registry.Describe(id)
	return meta, exists, nil
}
