package builtin

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/rules"
	nounsafetemplates "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_unsafe_templates"
	nozerowidth "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_zero_width"
)

// NewRegistry returns the registry containing built-in rules.
func NewRegistry() (*rules.Registry, error) {
	registry := rules.NewRegistry()
	zeroWidthRule := nozerowidth.New()
	if err := registry.Register(zeroWidthRule); err != nil {
		return nil, fmt.Errorf("register rule %q: %w", zeroWidthRule.Metadata().ID, err)
	}
	unsafeTemplatesRule := nounsafetemplates.New()
	if err := registry.Register(unsafeTemplatesRule); err != nil {
		return nil, fmt.Errorf("register rule %q: %w", unsafeTemplatesRule.Metadata().ID, err)
	}
	return registry, nil
}
