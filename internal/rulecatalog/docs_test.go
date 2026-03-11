package rulecatalog

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/ruledocs"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRule struct {
	meta rules.Metadata
}

func (r testRule) Metadata() rules.Metadata {
	return r.meta
}

func (r testRule) CheckDocument(_ rules.Context, _ rules.DocumentView) []rules.Finding {
	return nil
}

func Test_RuleCatalog_DocsURL(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ruledocs.URL("NoZeroWidth.md"), DocsURL(rules.Metadata{DocsFile: "NoZeroWidth.md"}))
	assert.Empty(t, DocsURL(rules.Metadata{}))
}

func Test_RuleCatalog_DocsURLIndex(t *testing.T) {
	t.Parallel()

	registry := rules.NewRegistry()
	require.NoError(t, registry.Register(testRule{
		meta: rules.Metadata{
			ID:              "built-in",
			Name:            "built-in",
			Summary:         "summary",
			Description:     "description",
			DocsFile:        "NoZeroWidth.md",
			DefaultSeverity: config.SeverityLow,
		},
	}))
	require.NoError(t, registry.Register(testRule{
		meta: rules.Metadata{
			ID:              "no-docs",
			Name:            "no-docs",
			Summary:         "summary",
			Description:     "description",
			DefaultSeverity: config.SeverityLow,
		},
	}))

	index := DocsURLIndex(registry, []config.CustomRule{{
		ID:       "custom-blocked-domain",
		Pattern:  "blocked",
		Severity: config.SeverityHigh,
		Message:  "blocked",
	}})

	assert.Equal(t, ruledocs.URL("NoZeroWidth.md"), index["built-in"])
	assert.Equal(t, ruledocs.URL(ruledocs.CustomDocFile), index["custom-blocked-domain"])
	assert.NotContains(t, index, "no-docs")
}
