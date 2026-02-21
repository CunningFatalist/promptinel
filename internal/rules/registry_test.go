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
