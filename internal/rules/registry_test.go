package rules

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Rules_Register_RejectsDuplicateIDs(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "a", DefaultSeverity: config.SeverityLow},
	})
	require.NoError(t, err)

	err = registry.Register(documentTestRule{
		meta: Metadata{ID: "a", DefaultSeverity: config.SeverityLow},
	})
	require.Error(t, err)
}

func Test_Rules_Compile_AppliesConfigOverrides(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta:     Metadata{ID: "first", DefaultSeverity: config.SeverityLow},
		findings: []Finding{{Message: "first"}},
	})
	require.NoError(t, err)
	err = registry.Register(documentTestRule{
		meta:     Metadata{ID: "second", DefaultSeverity: config.SeverityMedium},
		findings: []Finding{{Message: "second"}},
	})
	require.NoError(t, err)

	disableFirst := false
	compiled, err := registry.Compile(&config.Config{
		Rules: []config.Rule{
			{ID: "first", Enabled: &disableFirst},
			{ID: "second", Severity: config.SeverityHigh},
		},
	})
	require.NoError(t, err)

	findings := Evaluate(compiled, Context{}, "x")
	require.Len(t, findings, 1)
	assert.Equal(t, "second", findings[0].ID)
	assert.Equal(t, config.SeverityHigh, findings[0].Severity)
}

func Test_Rules_Evaluate_SetsIDAndSeverity(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta:     Metadata{ID: "first", DefaultSeverity: config.SeverityLow},
		findings: []Finding{{Message: "match"}},
	})
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)
	findings := Evaluate(compiled, Context{}, "x")
	require.Len(t, findings, 1)
	assert.Equal(t, "first", findings[0].ID)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
}

func Test_Rules_Register_RejectsEmptyID(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{DefaultSeverity: config.SeverityLow},
	})
	require.Error(t, err)
}

func Test_Rules_Register_RejectsInvalidDefaultSeverity(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "x", DefaultSeverity: config.Severity("invalid")},
	})
	require.Error(t, err)
}

func Test_Rules_Register_RejectsRuleWithoutPhaseChecks(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(noPhaseTestRule{
		meta: Metadata{ID: "x", DefaultSeverity: config.SeverityLow},
	})
	require.Error(t, err)
}

func Test_Rules_Register_RejectsNilRule(t *testing.T) {
	registry := NewRegistry()
	var rule *noPhaseTestRule
	err := registry.Register(rule)
	require.Error(t, err)
}

func Test_Rules_Compile_RejectsInvalidResolvedSeverity(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "x", DefaultSeverity: config.SeverityLow},
	})
	require.NoError(t, err)

	_, err = registry.Compile(&config.Config{Rules: []config.Rule{{ID: "x", Severity: config.Severity("invalid")}}})
	require.Error(t, err)
}

func Test_Rules_Compile_RejectsInvalidCustomRegex(t *testing.T) {
	registry := NewRegistry()
	_, err := registry.Compile(&config.Config{CustomRules: []config.CustomRule{{
		ID:       "bad",
		Pattern:  "[",
		Severity: config.SeverityLow,
		Message:  "bad",
	}}})
	require.Error(t, err)
}

func Test_Rules_Compile_RejectsInvalidCustomSeverity(t *testing.T) {
	registry := NewRegistry()
	_, err := registry.Compile(&config.Config{CustomRules: []config.CustomRule{{
		ID:       "bad",
		Pattern:  "x",
		Severity: config.Severity("invalid"),
		Message:  "bad",
	}}})
	require.Error(t, err)
}

func Test_Rules_Compile_RejectsDuplicateCustomRuleIDs(t *testing.T) {
	registry := NewRegistry()
	_, err := registry.Compile(&config.Config{CustomRules: []config.CustomRule{
		{
			ID:       "dup",
			Pattern:  "x",
			Severity: config.SeverityLow,
			Message:  "first",
		},
		{
			ID:       "dup",
			Pattern:  "y",
			Severity: config.SeverityMedium,
			Message:  "second",
		},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id")
}

func Test_Rules_Compile_RejectsCustomRuleIDConflictingWithBuiltIn(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "builtin", DefaultSeverity: config.SeverityLow},
	})
	require.NoError(t, err)

	_, err = registry.Compile(&config.Config{CustomRules: []config.CustomRule{
		{
			ID:       "builtin",
			Pattern:  "x",
			Severity: config.SeverityHigh,
			Message:  "conflict",
		},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id")
}

func Test_Rules_List_AndDescribe_NilRegistry(t *testing.T) {
	var registry *Registry
	assert.Nil(t, registry.List())
	meta, ok := registry.Describe("x")
	assert.False(t, ok)
	assert.Equal(t, Metadata{}, meta)
}

func Test_Rules_Compile_NilRegistry(t *testing.T) {
	var registry *Registry
	_, err := registry.Compile(nil)
	require.Error(t, err)
}

func Test_Rules_Register_NilRegistry(t *testing.T) {
	var registry *Registry
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "x", DefaultSeverity: config.SeverityLow},
	})
	require.Error(t, err)
}

func Test_Rules_List_ReturnsRegisteredMetadata(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "b", DefaultSeverity: config.SeverityLow},
	})
	require.NoError(t, err)
	err = registry.Register(documentTestRule{
		meta: Metadata{ID: "a", DefaultSeverity: config.SeverityLow},
	})
	require.NoError(t, err)

	list := registry.List()
	require.Len(t, list, 2)
	assert.Equal(t, "a", list[0].ID)
	assert.Equal(t, "b", list[1].ID)
}

func Test_Rules_Describe_ReturnsRuleMetadata(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(documentTestRule{
		meta: Metadata{ID: "x", Name: "Example", DefaultSeverity: config.SeverityMedium},
	})
	require.NoError(t, err)

	meta, ok := registry.Describe("x")
	require.True(t, ok)
	assert.Equal(t, "Example", meta.Name)
}

func Test_Rules_Compile_IncludesCustomRules(t *testing.T) {
	registry := NewRegistry()

	compiled, err := registry.Compile(&config.Config{
		CustomRules: []config.CustomRule{{
			ID:       "custom-curl",
			Pattern:  "curl",
			Severity: config.SeverityHigh,
			Message:  "curl found",
		}},
	})
	require.NoError(t, err)

	findings := Evaluate(compiled, Context{}, "run curl https://example.com")
	require.Len(t, findings, 1)
	assert.Equal(t, "custom-curl", findings[0].ID)
	assert.Equal(t, config.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "curl found", findings[0].Message)
}

func Test_Rules_Compile_CustomRegexReportsMatchPositionWithinToken(t *testing.T) {
	registry := NewRegistry()

	compiled, err := registry.Compile(&config.Config{
		CustomRules: []config.CustomRule{{
			ID:       "custom-url",
			Pattern:  "url",
			Severity: config.SeverityLow,
			Message:  "url found",
		}},
	})
	require.NoError(t, err)

	findings := Evaluate(compiled, Context{}, "run curl")
	require.Len(t, findings, 1)
	assert.Equal(t, Position{Line: 1, Column: 6}, findings[0].Position)
}

func Test_Rules_Compile_CustomRegexReportsDistinctPositionsForMultipleMatchesInToken(t *testing.T) {
	registry := NewRegistry()

	compiled, err := registry.Compile(&config.Config{
		CustomRules: []config.CustomRule{{
			ID:       "custom-a",
			Pattern:  "a",
			Severity: config.SeverityLow,
			Message:  "a found",
		}},
	})
	require.NoError(t, err)

	findings := Evaluate(compiled, Context{}, "banana")
	require.Len(t, findings, 3)
	assert.Equal(t, Position{Line: 1, Column: 2}, findings[0].Position)
	assert.Equal(t, Position{Line: 1, Column: 4}, findings[1].Position)
	assert.Equal(t, Position{Line: 1, Column: 6}, findings[2].Position)
}

func Test_Rules_CompileRule_SetsImplementedPhaseChecks(t *testing.T) {
	tests := []struct {
		name        string
		rule        Rule
		hasDocument bool
		hasSegment  bool
		hasTokens   bool
		hasFlow     bool
	}{
		{
			name:        "document",
			rule:        documentTestRule{meta: Metadata{ID: "document"}},
			hasDocument: true,
		},
		{
			name:       "segment",
			rule:       segmentTestRule{meta: Metadata{ID: "segment"}},
			hasSegment: true,
		},
		{
			name:      "tokens",
			rule:      tokenTestRule{meta: Metadata{ID: "tokens"}},
			hasTokens: true,
		},
		{
			name:    "flow",
			rule:    flowTestRule{meta: Metadata{ID: "flow"}},
			hasFlow: true,
		},
		{
			name:        "document-and-flow",
			rule:        documentAndFlowTestRule{meta: Metadata{ID: "document-and-flow"}},
			hasDocument: true,
			hasFlow:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compiled := compileRule(tc.rule, "compiled-id", config.SeverityHigh)

			assert.Equal(t, "compiled-id", compiled.ID)
			assert.Equal(t, config.SeverityHigh, compiled.Severity)
			assert.Equal(t, tc.hasDocument, compiled.checkDocument != nil)
			assert.Equal(t, tc.hasSegment, compiled.checkSegment != nil)
			assert.Equal(t, tc.hasTokens, compiled.checkTokens != nil)
			assert.Equal(t, tc.hasFlow, compiled.checkFlow != nil)
		})
	}
}

func Test_Rules_SupportsAtLeastOnePhase_ReturnsExpectedResult(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		expected bool
	}{
		{
			name:     "no-phase",
			rule:     noPhaseTestRule{meta: Metadata{ID: "none"}},
			expected: false,
		},
		{
			name:     "document",
			rule:     documentTestRule{meta: Metadata{ID: "document"}},
			expected: true,
		},
		{
			name:     "segment",
			rule:     segmentTestRule{meta: Metadata{ID: "segment"}},
			expected: true,
		},
		{
			name:     "tokens",
			rule:     tokenTestRule{meta: Metadata{ID: "tokens"}},
			expected: true,
		},
		{
			name:     "flow",
			rule:     flowTestRule{meta: Metadata{ID: "flow"}},
			expected: true,
		},
		{
			name:     "document-and-flow",
			rule:     documentAndFlowTestRule{meta: Metadata{ID: "document-and-flow"}},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, supportsAtLeastOnePhase(tc.rule))
		})
	}
}

type segmentTestRule struct {
	meta Metadata
}

func (r segmentTestRule) Metadata() Metadata {
	return r.meta
}

func (r segmentTestRule) CheckSegment(_ Context, _ Segment) []Finding {
	return nil
}

type tokenTestRule struct {
	meta Metadata
}

func (r tokenTestRule) Metadata() Metadata {
	return r.meta
}

func (r tokenTestRule) CheckTokens(_ Context, _ Segment, _ []Token) []Finding {
	return nil
}

type flowTestRule struct {
	meta Metadata
}

func (r flowTestRule) Metadata() Metadata {
	return r.meta
}

func (r flowTestRule) CheckFlow(_ Context, _ AnalyzedDocument) []Finding {
	return nil
}

type documentAndFlowTestRule struct {
	meta Metadata
}

func (r documentAndFlowTestRule) Metadata() Metadata {
	return r.meta
}

func (r documentAndFlowTestRule) CheckDocument(_ Context, _ DocumentView) []Finding {
	return nil
}

func (r documentAndFlowTestRule) CheckFlow(_ Context, _ AnalyzedDocument) []Finding {
	return nil
}
