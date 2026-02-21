package engine

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

type documentRuleForTest struct {
	meta     rules.Metadata
	findings []rules.Finding
}

func (r documentRuleForTest) Metadata() rules.Metadata {
	return r.meta
}

func (r documentRuleForTest) CheckDocument(_ rules.Context, _ rules.DocumentView) []rules.Finding {
	cloned := make([]rules.Finding, len(r.findings))
	copy(cloned, r.findings)
	return cloned
}

func newAlwaysRule(id string, severity config.Severity, findingMessage string) documentRuleForTest {
	return documentRuleForTest{
		meta: rules.Metadata{
			ID:              id,
			DefaultSeverity: severity,
		},
		findings: []rules.Finding{{
			Message:  findingMessage,
			Position: rules.Position{Line: 1, Column: 1},
		}},
	}
}
