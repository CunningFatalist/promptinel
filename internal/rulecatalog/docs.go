package rulecatalog

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/ruledocs"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/scanfinding"
)

// DocsURL returns the documentation URL for rule metadata when available.
func DocsURL(meta rules.Metadata) string {
	return ruledocs.URL(meta.DocsFile)
}

// DocsURLIndex returns documentation URLs keyed by rule ID for built-in and custom rules.
func DocsURLIndex(registry *rules.Registry, customRules []config.CustomRule) map[string]string {
	size := len(customRules)
	if registry != nil {
		size += len(registry.List())
	}

	index := make(map[string]string, size)
	if registry != nil {
		for _, meta := range registry.List() {
			if docsURL := DocsURL(meta); docsURL != "" {
				index[meta.ID] = docsURL
			}
		}
	}

	customDocsURL := ruledocs.URL(ruledocs.CustomDocFile)
	if customDocsURL != "" {
		for _, rule := range customRules {
			if isInternalDiagnosticRuleID(rule.ID) {
				continue
			}
			index[rule.ID] = customDocsURL
		}
	}

	return index
}

func isInternalDiagnosticRuleID(id string) bool {
	switch id {
	case scanfinding.OversizedFileSkipID, scanfinding.UnreadableFileSkipID:
		return true
	default:
		return false
	}
}
