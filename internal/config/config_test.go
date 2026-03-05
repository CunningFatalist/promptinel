package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Config_Severity_IsValid(t *testing.T) {
	low := SeverityLow
	medium := SeverityMedium
	high := SeverityHigh
	invalid := Severity("invalid")

	assert.True(t, low.IsValid())
	assert.True(t, medium.IsValid())
	assert.True(t, high.IsValid())
	assert.False(t, invalid.IsValid())
}

func Test_Config_Severity_String(t *testing.T) {
	low := SeverityLow
	medium := SeverityMedium
	high := SeverityHigh

	assert.Equal(t, "low", low.String())
	assert.Equal(t, "medium", medium.String())
	assert.Equal(t, "high", high.String())
}

func Test_Config_SeverityRank(t *testing.T) {
	assert.Equal(t, 1, SeverityRank(SeverityLow))
	assert.Equal(t, 2, SeverityRank(SeverityMedium))
	assert.Equal(t, 3, SeverityRank(SeverityHigh))
}

func Test_Config_SeverityAtLeast(t *testing.T) {
	assert.True(t, SeverityAtLeast(SeverityHigh, SeverityMedium))
	assert.True(t, SeverityAtLeast(SeverityMedium, SeverityMedium))
	assert.False(t, SeverityAtLeast(SeverityLow, SeverityMedium))
}

func Test_Config_Severity_MarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{"low", SeverityLow, "low"},
		{"medium", SeverityMedium, "medium"},
		{"high", SeverityHigh, "high"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.severity.MarshalYAML()
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func Test_Config_Severity_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Severity
		wantErr bool
	}{
		{"low", "low", SeverityLow, false},
		{"medium", "medium", SeverityMedium, false},
		{"high", "high", SeverityHigh, false},
		{"uppercase", "HIGH", SeverityHigh, false},
		{"mixed case", "MeDiUm", SeverityMedium, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s Severity
			err := s.UnmarshalYAML(func(v any) error {
				*v.(*string) = tt.input
				return nil
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, s)
			}
		})
	}
}

func Test_Config_Severity_UnmarshalYAML_Error(t *testing.T) {
	var s Severity
	err := s.UnmarshalYAML(func(v any) error {
		return assert.AnError
	})
	assert.Error(t, err)
}

func Test_Config_TrustLevel_IsValid(t *testing.T) {
	trusted := TrustLevelTrusted
	untrusted := TrustLevelUntrusted
	tainted := TrustLevelTainted
	invalid := TrustLevel("invalid")

	assert.True(t, trusted.IsValid())
	assert.True(t, untrusted.IsValid())
	assert.True(t, tainted.IsValid())
	assert.False(t, invalid.IsValid())
}

func Test_Config_TrustLevel_String(t *testing.T) {
	trusted := TrustLevelTrusted
	untrusted := TrustLevelUntrusted
	tainted := TrustLevelTainted

	assert.Equal(t, "trusted", trusted.String())
	assert.Equal(t, "untrusted", untrusted.String())
	assert.Equal(t, "tainted", tainted.String())
}

func Test_Config_TrustLevel_MarshalYAML(t *testing.T) {
	tests := []struct {
		name       string
		trustLevel TrustLevel
		want       string
	}{
		{"trusted", TrustLevelTrusted, "trusted"},
		{"untrusted", TrustLevelUntrusted, "untrusted"},
		{"tainted", TrustLevelTainted, "tainted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.trustLevel.MarshalYAML()
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func Test_Config_TrustLevel_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    TrustLevel
		wantErr bool
	}{
		{"trusted", "trusted", TrustLevelTrusted, false},
		{"untrusted", "untrusted", TrustLevelUntrusted, false},
		{"tainted", "tainted", TrustLevelTainted, false},
		{"uppercase", "TRUSTED", TrustLevelTrusted, false},
		{"mixed case", "UnTrUsTeD", TrustLevelUntrusted, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tl TrustLevel
			err := tl.UnmarshalYAML(func(v any) error {
				*v.(*string) = tt.input
				return nil
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, tl)
			}
		})
	}
}

func Test_Config_TrustLevel_UnmarshalYAML_Error(t *testing.T) {
	var tl TrustLevel
	err := tl.UnmarshalYAML(func(v any) error {
		return assert.AnError
	})
	assert.Error(t, err)
}

func Test_Config_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, SeverityHigh, cfg.Policy.FailOn)
	assert.Equal(t, SeverityMedium, cfg.Policy.WarnOn)

	assert.True(t, cfg.Environment.CanExecuteShell)
	assert.True(t, cfg.Environment.CanAccessFilesystem)
	assert.True(t, cfg.Environment.CanAccessNetwork)
	assert.True(t, cfg.Environment.HasSecrets)

	assert.Equal(t, TrustLevelTrusted, cfg.Trust.LocalFiles)
	assert.Equal(t, TrustLevelUntrusted, cfg.Trust.RemoteIncludes)
	assert.Equal(t, TrustLevelTainted, cfg.Trust.UserInputPlaceholders)
	assert.Equal(t, DefaultMaxFileSizeBytes, cfg.Limits.MaxFileSizeBytes)
	assert.Empty(t, cfg.Filters.Include)
	assert.Empty(t, cfg.Filters.Exclude)

	assert.Empty(t, cfg.Scopes)
	assert.Empty(t, cfg.Rules)
	assert.Empty(t, cfg.CustomRules)
}

func Test_Config_Load_NoConfigFile(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, DefaultConfig(), cfg)
}

func Test_Config_LoadWithOptions_NoDiscovery_UsesDefaultsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")
	configContent := `
policy:
  fail-on: low
  warn-on: low
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	previousWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})

	cfg, err := LoadWithOptions("", LoadOptions{Discover: false})
	require.NoError(t, err)
	assert.Equal(t, SeverityHigh, cfg.Policy.FailOn)
	assert.Equal(t, SeverityMedium, cfg.Policy.WarnOn)
}

func Test_Config_LoadWithOptions_NoDiscovery_StillLoadsExplicitFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")
	configContent := `
policy:
  fail-on: low
  warn-on: low
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	cfg, err := LoadWithOptions(configPath, LoadOptions{Discover: false})
	require.NoError(t, err)
	assert.Equal(t, SeverityLow, cfg.Policy.FailOn)
	assert.Equal(t, SeverityLow, cfg.Policy.WarnOn)
}

func Test_Config_Load_ValidConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: high
  warn-on: medium

environment:
  can_execute_shell: false
  can_access_filesystem: false
  can_access_network: false
  has_secrets: false

trust:
  local-files: untrusted
  remote-includes: tainted
  user-input-placeholders: trusted

limits:
  max_file_size_bytes: 12345

filters:
  include:
    - "*.md"
  exclude:
    - "*.yaml"

scopes:
  - path: agents/**
    severity: high
    rules:
      - id: no-zero-width
        enabled: false
  - path: docs/**
    severity: low

rules:
  - id: no-zero-width
    enabled: true
  - id: no-shell-commands
    severity: high

custom-rules:
  - id: test-rule
    pattern: "test.*pattern"
    severity: medium
    message: "Test rule message"
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, SeverityHigh, cfg.Policy.FailOn)
	assert.Equal(t, SeverityMedium, cfg.Policy.WarnOn)

	assert.False(t, cfg.Environment.CanExecuteShell)
	assert.False(t, cfg.Environment.CanAccessFilesystem)
	assert.False(t, cfg.Environment.CanAccessNetwork)
	assert.False(t, cfg.Environment.HasSecrets)

	assert.Equal(t, TrustLevelUntrusted, cfg.Trust.LocalFiles)
	assert.Equal(t, TrustLevelTainted, cfg.Trust.RemoteIncludes)
	assert.Equal(t, TrustLevelTrusted, cfg.Trust.UserInputPlaceholders)
	assert.Equal(t, int64(12345), cfg.Limits.MaxFileSizeBytes)
	assert.Equal(t, []string{"*.md"}, cfg.Filters.Include)
	assert.Equal(t, []string{"*.yaml"}, cfg.Filters.Exclude)

	require.Len(t, cfg.Scopes, 2)
	assert.Equal(t, "agents/**", cfg.Scopes[0].Path)
	assert.Equal(t, SeverityHigh, cfg.Scopes[0].Severity)
	require.Len(t, cfg.Scopes[0].Rules, 1)
	assert.Equal(t, "no-zero-width", cfg.Scopes[0].Rules[0].ID)
	require.NotNil(t, cfg.Scopes[0].Rules[0].Enabled)
	assert.False(t, *cfg.Scopes[0].Rules[0].Enabled)
	assert.Equal(t, "docs/**", cfg.Scopes[1].Path)
	assert.Equal(t, SeverityLow, cfg.Scopes[1].Severity)

	require.Len(t, cfg.Rules, 2)
	assert.Equal(t, "no-zero-width", cfg.Rules[0].ID)
	require.NotNil(t, cfg.Rules[0].Enabled)
	assert.True(t, *cfg.Rules[0].Enabled)
	assert.Equal(t, "no-shell-commands", cfg.Rules[1].ID)
	assert.Equal(t, SeverityHigh, cfg.Rules[1].Severity)

	require.Len(t, cfg.CustomRules, 1)
	assert.Equal(t, "test-rule", cfg.CustomRules[0].ID)
	assert.Equal(t, "test.*pattern", cfg.CustomRules[0].Pattern)
	assert.Equal(t, SeverityMedium, cfg.CustomRules[0].Severity)
	assert.Equal(t, "Test rule message", cfg.CustomRules[0].Message)
}

func Test_Config_Load_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0o644)
	require.NoError(t, err)

	_, err = Load(configPath)
	assert.Error(t, err)
}

func Test_Config_Load_InvalidConfigValues(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: invalid-severity
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	_, err = Load(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func Test_Config_Load_InvalidCustomRulePattern(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
custom-rules:
  - id: bad-regex
    pattern: "[invalid"
    severity: medium
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	_, err = Load(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func Test_Config_Load_InvalidScopePattern(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
scopes:
  - path: "invalid["
    severity: low
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	_, err = Load(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid glob pattern")
}

func Test_Config_Load_InvalidIncludeFilterPattern(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
filters:
  include:
    - "invalid["
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	_, err = Load(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid glob pattern for filters.include")
}

func Test_Config_LoadFromPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: medium
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	cfg, err := LoadFromPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, SeverityMedium, cfg.Policy.FailOn)
}

func Test_Config_LoadFromPath_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: low
  warn-on: low
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	cfg, err := LoadFromPath(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, SeverityLow, cfg.Policy.FailOn)
}

func Test_Config_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	assert.NoError(t, cfg.Validate())
}

func Test_Config_Validate_InvalidFailOn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.FailOn = "invalid"
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy.fail-on severity")
}

func Test_Config_Validate_InvalidWarnOn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.WarnOn = "invalid"
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy.warn-on severity")
}

func Test_Config_Validate_InvalidPolicyOrdering_FailBelowWarn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.FailOn = SeverityMedium
	cfg.Policy.WarnOn = SeverityHigh
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy severity ordering")
}

func Test_Config_Validate_InvalidLocalFiles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Trust.LocalFiles = "invalid"
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust.local-files level")
}

func Test_Config_Validate_InvalidRemoteIncludes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Trust.RemoteIncludes = "invalid"
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust.remote-includes level")
}

func Test_Config_Validate_InvalidUserInputPlaceholders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Trust.UserInputPlaceholders = "invalid"
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust.user-input-placeholders level")
}

func Test_Config_Validate_InvalidMaxFileSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxFileSizeBytes = 0
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid limits.max_file_size_bytes")
}

func Test_Config_Validate_InvalidScopeSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scopes = []Scope{{Path: "test/**", Severity: "invalid"}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for scope")
}

func Test_Config_Validate_InvalidScopeGlobPattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scopes = []Scope{{Path: "test[", Severity: SeverityLow}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid glob pattern for scope")
}

func Test_Config_Validate_ScopeRuleWithEmptyID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scopes = []Scope{{
		Path: "docs/**",
		Rules: []Rule{
			{ID: "", Severity: SeverityLow},
		},
	}}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scope[0].rules[0] has empty id")
}

func Test_Config_Validate_InvalidScopeRuleSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scopes = []Scope{{
		Path: "docs/**",
		Rules: []Rule{
			{ID: "no-zero-width", Severity: "invalid"},
		},
	}}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for scope[0].rules[0]")
}

func Test_Config_Validate_InvalidIncludeFilterGlobPattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filters.Include = []string{"test["}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid glob pattern for filters.include")
}

func Test_Config_Validate_EmptyRuleID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{ID: ""}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has empty id")
}

func Test_Config_Validate_RuleWithEmptySeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{ID: "test-rule", Severity: ""}}
	assert.NoError(t, cfg.Validate())
}

func Test_Config_Validate_RuleWithValidSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{ID: "test-rule", Severity: SeverityHigh}}
	assert.NoError(t, cfg.Validate())
}

func Test_Config_Validate_InvalidRuleSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{ID: "test-rule", Severity: "invalid"}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for rule")
}

func Test_Config_Validate_DuplicateRuleID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{
		{ID: "duplicate-rule", Severity: SeverityLow},
		{ID: "duplicate-rule", Severity: SeverityHigh},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id")
}

func Test_Config_Validate_EmptyCustomRuleID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{ID: "", Pattern: "test"}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has empty id")
}

func Test_Config_Validate_EmptyCustomRulePattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{ID: "test-rule", Pattern: ""}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has empty pattern")
}

func Test_Config_Validate_InvalidCustomRuleSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{ID: "test-rule", Pattern: "test", Severity: "invalid"}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for custom-rule")
}

func Test_Config_Validate_InvalidCustomRulePattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{{ID: "test-rule", Pattern: "[invalid(regex", Severity: SeverityMedium}}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern for custom-rule")
}

func Test_Config_Validate_DuplicateCustomRuleID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{
		{ID: "duplicate-custom-rule", Pattern: "first", Severity: SeverityLow},
		{ID: "duplicate-custom-rule", Pattern: "second", Severity: SeverityMedium},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate custom-rule id")
}

func Test_Config_GetRuleByID(t *testing.T) {
	cfg := DefaultConfig()
	enabled := true
	disabled := false
	cfg.Rules = []Rule{
		{ID: "rule-1", Enabled: &enabled},
		{ID: "rule-2", Enabled: &disabled},
	}

	rule := cfg.GetRuleByID("rule-1")
	require.NotNil(t, rule)
	assert.Equal(t, "rule-1", rule.ID)
	require.NotNil(t, rule.Enabled)
	assert.True(t, *rule.Enabled)

	rule = cfg.GetRuleByID("rule-2")
	require.NotNil(t, rule)
	require.NotNil(t, rule.Enabled)
	assert.False(t, *rule.Enabled)

	rule = cfg.GetRuleByID("non-existent")
	assert.Nil(t, rule)
}

func Test_Config_GetCustomRuleByID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomRules = []CustomRule{
		{ID: "custom-1", Pattern: "pattern1"},
		{ID: "custom-2", Pattern: "pattern2"},
	}

	rule := cfg.GetCustomRuleByID("custom-1")
	require.NotNil(t, rule)
	assert.Equal(t, "pattern1", rule.Pattern)

	rule = cfg.GetCustomRuleByID("non-existent")
	assert.Nil(t, rule)
}

func Test_Config_GetScopeForPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scopes = []Scope{
		{Path: "agents/**", Severity: SeverityHigh},
		{Path: "docs/**", Severity: SeverityLow},
	}

	scope := cfg.GetScopeForPath("agents/test.md")
	require.NotNil(t, scope)
	assert.Equal(t, SeverityHigh, scope.Severity)

	scope = cfg.GetScopeForPath("docs/readme.md")
	require.NotNil(t, scope)
	assert.Equal(t, SeverityLow, scope.Severity)

	scope = cfg.GetScopeForPath("agents/nested/test.md")
	require.NotNil(t, scope)
	assert.Equal(t, SeverityHigh, scope.Severity)

	scope = cfg.GetScopeForPath("other/file.md")
	assert.Nil(t, scope)
}

func Test_Config_GetScopeForPath_OverlappingScopes_LastWins(t *testing.T) {
	cfg := DefaultConfig()
	disabled := false
	cfg.Scopes = []Scope{
		{
			Path:     "docs/**",
			Severity: SeverityLow,
			Rules: []Rule{
				{ID: "no-unsafe-templates", Enabled: &disabled},
				{ID: "no-bidi-control-characters", Severity: SeverityLow},
			},
		},
		{
			Path:     "docs/security/**",
			Severity: SeverityHigh,
			Rules: []Rule{
				{ID: "no-bidi-control-characters", Severity: SeverityMedium},
			},
		},
	}

	scope := cfg.GetScopeForPath("docs/security/model.md")
	require.NotNil(t, scope)
	assert.Equal(t, "docs/security/**", scope.Path)
	assert.Equal(t, SeverityHigh, scope.Severity)
	require.Len(t, scope.Rules, 2)
	assert.Equal(t, "no-unsafe-templates", scope.Rules[0].ID)
	require.NotNil(t, scope.Rules[0].Enabled)
	assert.False(t, *scope.Rules[0].Enabled)
	assert.Equal(t, "no-bidi-control-characters", scope.Rules[1].ID)
	assert.Equal(t, SeverityMedium, scope.Rules[1].Severity)
}

func Test_Config_GetScopeForPath_OverlappingScopeRuleOverrides_MergesFields(t *testing.T) {
	cfg := DefaultConfig()
	disabled := false
	cfg.Scopes = []Scope{
		{
			Path: "docs/**",
			Rules: []Rule{
				{ID: "no-bidi-control-characters", Enabled: &disabled, Severity: SeverityLow},
			},
		},
		{
			Path: "docs/security/**",
			Rules: []Rule{
				{ID: "no-bidi-control-characters", Severity: SeverityHigh},
			},
		},
	}

	scope := cfg.GetScopeForPath("docs/security/model.md")
	require.NotNil(t, scope)
	require.Len(t, scope.Rules, 1)
	assert.Equal(t, "no-bidi-control-characters", scope.Rules[0].ID)
	require.NotNil(t, scope.Rules[0].Enabled)
	assert.False(t, *scope.Rules[0].Enabled)
	assert.Equal(t, SeverityHigh, scope.Rules[0].Severity)
}

func Test_Config_ValidateScopedRuleIDs_RejectsUnknownRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scopes = []Scope{
		{
			Path: "docs/**",
			Rules: []Rule{
				{ID: "unknown-rule"},
			},
		},
	}

	err := cfg.ValidateScopedRuleIDs(map[string]struct{}{
		"no-unsafe-templates": {},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rule id")
	assert.Contains(t, err.Error(), "scopes[0].rules[0]")
}
