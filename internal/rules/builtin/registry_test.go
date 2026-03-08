package builtin

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Builtin_NewRegistry_ContainsDefaultRules(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	list := registry.List()
	expectedIDs := []string{
		"no-bidi-control-characters",
		"no-command-chaining",
		"no-curl-pipe-shell",
		"no-data-uri-payloads",
		"no-dns-exfiltration",
		"no-download-execute",
		"no-gitconfig-credential-helper",
		"no-hidden-directionality",
		"no-hidden-html-instructions",
		"no-insecure-http",
		"no-interpreter-inline-exec",
		"no-metadata-service-access",
		"no-mixed-script-identifiers",
		"no-multilayer-encoding",
		"no-nonstandard-whitespace",
		"no-override-capability-flow",
		"no-powershell-download-cradle",
		"no-prompt-injection-override",
		"no-role-header-spoofing",
		"no-secret-exfiltration-intent",
		"no-secret-to-network-flow",
		"no-sensitive-file-paths",
		"no-shell-heredoc-payload",
		"no-shell-profile-modification",
		"no-ssh-config-manipulation",
		"no-staged-download-execution",
		"no-suspicious-base64",
		"no-tainted-placeholder-instructions",
		"no-template-network-fetch",
		"no-transcript-injection",
		"no-tunnel-and-reverse-shell",
		"no-unsafe-templates",
		"no-url-encoded-command-payload",
		"no-webhook-exfiltration",
		"no-yaml-json-role-fields",
		"no-zero-width",
		"skill-has-bundled-resources",
	}
	require.Len(t, list, len(expectedIDs))
	for i, id := range expectedIDs {
		assert.Equal(t, id, list[i].ID)
	}
}

func Test_Builtin_NewRegistry_DescribeKnownRule(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	meta, ok := registry.Describe("no-zero-width")
	require.True(t, ok)
	assert.Equal(t, "No Zero Width Characters", meta.Name)
}

type stubRule struct {
	documentFindings []rules.Finding
	segmentFindings  []rules.Finding
	tokenFindings    []rules.Finding
	flowFindings     []rules.Finding
}

func (r stubRule) Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              "stub-rule",
		Name:            "Stub Rule",
		DefaultSeverity: config.SeverityMedium,
	}
}

func (r stubRule) CheckDocument(_ rules.Context, _ rules.DocumentView) []rules.Finding {
	return r.documentFindings
}

func (r stubRule) CheckSegment(_ rules.Context, _ rules.Segment) []rules.Finding {
	return r.segmentFindings
}

func (r stubRule) CheckTokens(_ rules.Context, _ rules.Segment, _ []rules.Token) []rules.Finding {
	return r.tokenFindings
}

func (r stubRule) CheckFlow(_ rules.Context, _ rules.AnalyzedDocument) []rules.Finding {
	return r.flowFindings
}

type metadataOnlyRule struct{}

func (metadataOnlyRule) Metadata() rules.Metadata {
	return rules.Metadata{ID: "metadata-only", Name: "Metadata Only"}
}

func Test_Builtin_DocumentedRule_DelegatesSupportedInterfaces(t *testing.T) {
	rule := documentedRule{
		Rule: stubRule{
			documentFindings: []rules.Finding{{Message: "document"}},
			segmentFindings:  []rules.Finding{{Message: "segment"}},
			tokenFindings:    []rules.Finding{{Message: "token"}},
			flowFindings:     []rules.Finding{{Message: "flow"}},
		},
		docsFile: "StubRule.md",
	}

	assert.Equal(t, "StubRule.md", rule.Metadata().DocsFile)
	assert.Len(t, rule.CheckDocument(rules.Context{}, rules.DocumentView{}), 1)
	assert.Len(t, rule.CheckSegment(rules.Context{}, rules.Segment{}), 1)
	assert.Len(t, rule.CheckTokens(rules.Context{}, rules.Segment{}, nil), 1)
	assert.Len(t, rule.CheckFlow(rules.Context{}, rules.AnalyzedDocument{}), 1)
}

func Test_Builtin_DocumentedRule_ReturnsNilForUnsupportedInterfaces(t *testing.T) {
	rule := documentedRule{Rule: metadataOnlyRule{}, docsFile: "MetadataOnly.md"}

	assert.Nil(t, rule.CheckDocument(rules.Context{}, rules.DocumentView{}))
	assert.Nil(t, rule.CheckSegment(rules.Context{}, rules.Segment{}))
	assert.Nil(t, rule.CheckTokens(rules.Context{}, rules.Segment{}, nil))
	assert.Nil(t, rule.CheckFlow(rules.Context{}, rules.AnalyzedDocument{}))
}
