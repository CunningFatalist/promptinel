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

func (r customRegexRule) CheckTokens(_ Context, _ Segment, tokens []Token) []Finding {
	findings := make([]Finding, 0)
	for _, token := range tokens {
		matches := r.pattern.FindAllStringIndex(token.Value, -1)
		for range matches {
			findings = append(findings, Finding{
				Message:  r.message,
				Position: token.Position,
			})
		}
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
