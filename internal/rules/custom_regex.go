package rules

import (
	"fmt"
	"regexp"

	"github.com/CunningFatalist/promptinel/internal/config"
)

type customRegexRule struct {
	metadata Metadata
	pattern  *regexp.Regexp
	message  string
}

func (r customRegexRule) Metadata() Metadata {
	return r.metadata
}

func (r customRegexRule) CheckDocument(_ Context, doc DocumentView) []Finding {
	matches := r.pattern.FindAllStringIndex(doc.Content, -1)
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, Finding{
			Message:  r.message,
			Position: PositionFromByteOffset(doc.Content, match[0]),
		})
	}
	return findings
}

func compileCustomRule(cfg config.CustomRule) (Rule, error) {
	compiledPattern, err := regexp.Compile(cfg.Pattern)
	if err != nil {
		return nil, fmt.Errorf("compile custom rule %q: %w", cfg.ID, err)
	}

	return customRegexRule{
		metadata: Metadata{
			ID:              cfg.ID,
			Name:            cfg.ID,
			Summary:         "Custom regex rule",
			Description:     "User-defined regex-based rule from configuration.",
			DefaultSeverity: cfg.Severity,
		},
		pattern: compiledPattern,
		message: cfg.Message,
	}, nil
}
