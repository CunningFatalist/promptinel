package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Config_Severity_IsValid(t *testing.T) {
	assert.True(t, SeverityLow.IsValid())
	assert.True(t, SeverityMedium.IsValid())
	assert.True(t, SeverityHigh.IsValid())
	assert.False(t, Severity("invalid").IsValid())
}

func Test_Config_Severity_String(t *testing.T) {
	assert.Equal(t, "low", SeverityLow.String())
	assert.Equal(t, "medium", SeverityMedium.String())
	assert.Equal(t, "high", SeverityHigh.String())
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
			err := s.UnmarshalYAML(func(v interface{}) error {
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
	err := s.UnmarshalYAML(func(v interface{}) error {
		return assert.AnError
	})
	assert.Error(t, err)
}

func Test_Config_TrustLevel_IsValid(t *testing.T) {
	assert.True(t, TrustLevelTrusted.IsValid())
	assert.True(t, TrustLevelUntrusted.IsValid())
	assert.True(t, TrustLevelTainted.IsValid())
	assert.False(t, TrustLevel("invalid").IsValid())
}

func Test_Config_TrustLevel_String(t *testing.T) {
	assert.Equal(t, "trusted", TrustLevelTrusted.String())
	assert.Equal(t, "untrusted", TrustLevelUntrusted.String())
	assert.Equal(t, "tainted", TrustLevelTainted.String())
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
			err := tl.UnmarshalYAML(func(v interface{}) error {
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
	err := tl.UnmarshalYAML(func(v interface{}) error {
		return assert.AnError
	})
	assert.Error(t, err)
}

func Test_Config_DefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, SeverityHigh, config.Policy.FailOn)
	assert.Equal(t, SeverityMedium, config.Policy.WarnOn)
	assert.Equal(t, SeverityLow, config.Policy.IgnoreOn)

	assert.True(t, config.Environment.CanExecuteShell)
	assert.True(t, config.Environment.CanAccessFilesystem)
	assert.True(t, config.Environment.CanAccessNetwork)
	assert.True(t, config.Environment.HasSecrets)

	assert.Equal(t, TrustLevelTrusted, config.Trust.LocalFiles)
	assert.Equal(t, TrustLevelUntrusted, config.Trust.RemoteIncludes)
	assert.Equal(t, TrustLevelTainted, config.Trust.UserInputPlaceholders)

	assert.Empty(t, config.Scopes)
	assert.Empty(t, config.Rules)
	assert.Empty(t, config.CustomRules)
}

func Test_Config_Load_NoConfigFile(t *testing.T) {
	config, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, DefaultConfig(), config)
}

func Test_Config_Load_ValidConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: high
  warn-on: medium
  ignore-on: low

environment:
  can_execute_shell: false
  can_access_filesystem: false
  can_access_network: false
  has_secrets: false

trust:
  local-files: untrusted
  remote-includes: tainted
  user-input-placeholders: trusted

scopes:
  - path: agents/**
    severity: high
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

	config, err := Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, SeverityHigh, config.Policy.FailOn)
	assert.Equal(t, SeverityMedium, config.Policy.WarnOn)
	assert.Equal(t, SeverityLow, config.Policy.IgnoreOn)

	assert.False(t, config.Environment.CanExecuteShell)
	assert.False(t, config.Environment.CanAccessFilesystem)
	assert.False(t, config.Environment.CanAccessNetwork)
	assert.False(t, config.Environment.HasSecrets)

	assert.Equal(t, TrustLevelUntrusted, config.Trust.LocalFiles)
	assert.Equal(t, TrustLevelTainted, config.Trust.RemoteIncludes)
	assert.Equal(t, TrustLevelTrusted, config.Trust.UserInputPlaceholders)

	require.Len(t, config.Scopes, 2)
	assert.Equal(t, "agents/**", config.Scopes[0].Path)
	assert.Equal(t, SeverityHigh, config.Scopes[0].Severity)
	assert.Equal(t, "docs/**", config.Scopes[1].Path)
	assert.Equal(t, SeverityLow, config.Scopes[1].Severity)

	require.Len(t, config.Rules, 2)
	assert.Equal(t, "no-zero-width", config.Rules[0].ID)
	assert.True(t, config.Rules[0].Enabled)
	assert.Equal(t, "no-shell-commands", config.Rules[1].ID)
	assert.Equal(t, SeverityHigh, config.Rules[1].Severity)

	require.Len(t, config.CustomRules, 1)
	assert.Equal(t, "test-rule", config.CustomRules[0].ID)
	assert.Equal(t, "test.*pattern", config.CustomRules[0].Pattern)
	assert.Equal(t, SeverityMedium, config.CustomRules[0].Severity)
	assert.Equal(t, "Test rule message", config.CustomRules[0].Message)
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

func Test_Config_LoadFromPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: medium
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	config, err := LoadFromPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, SeverityMedium, config.Policy.FailOn)
}

func Test_Config_LoadFromPath_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".promptinel.yaml")

	configContent := `
policy:
  fail-on: low
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	config, err := LoadFromPath(tmpDir)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, SeverityLow, config.Policy.FailOn)
}

func Test_Config_Validate_Valid(t *testing.T) {
	config := DefaultConfig()
	assert.NoError(t, config.Validate())
}

func Test_Config_Validate_InvalidFailOn(t *testing.T) {
	config := DefaultConfig()
	config.Policy.FailOn = "invalid"
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy.fail-on severity")
}

func Test_Config_Validate_InvalidWarnOn(t *testing.T) {
	config := DefaultConfig()
	config.Policy.WarnOn = "invalid"
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy.warn-on severity")
}

func Test_Config_Validate_InvalidIgnoreOn(t *testing.T) {
	config := DefaultConfig()
	config.Policy.IgnoreOn = "invalid"
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy.ignore-on severity")
}

func Test_Config_Validate_InvalidLocalFiles(t *testing.T) {
	config := DefaultConfig()
	config.Trust.LocalFiles = "invalid"
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust.local-files level")
}

func Test_Config_Validate_InvalidRemoteIncludes(t *testing.T) {
	config := DefaultConfig()
	config.Trust.RemoteIncludes = "invalid"
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust.remote-includes level")
}

func Test_Config_Validate_InvalidUserInputPlaceholders(t *testing.T) {
	config := DefaultConfig()
	config.Trust.UserInputPlaceholders = "invalid"
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust.user-input-placeholders level")
}

func Test_Config_Validate_InvalidScopeSeverity(t *testing.T) {
	config := DefaultConfig()
	config.Scopes = []Scope{{Path: "test/**", Severity: "invalid"}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for scope")
}

func Test_Config_Validate_InvalidScopeGlobPattern(t *testing.T) {
	config := DefaultConfig()
	config.Scopes = []Scope{{Path: "test[", Severity: SeverityLow}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid glob pattern for scope")
}

func Test_Config_Validate_EmptyRuleID(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: ""}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has empty id")
}

func Test_Config_Validate_RuleWithEmptySeverity(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "test-rule", Severity: ""}}
	assert.NoError(t, config.Validate())
}

func Test_Config_Validate_RuleWithValidSeverity(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "test-rule", Severity: SeverityHigh}}
	assert.NoError(t, config.Validate())
}

func Test_Config_Validate_InvalidRuleSeverity(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "test-rule", Severity: "invalid"}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for rule")
}

func Test_Config_Validate_EmptyCustomRuleID(t *testing.T) {
	config := DefaultConfig()
	config.CustomRules = []CustomRule{{ID: "", Pattern: "test"}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has empty id")
}

func Test_Config_Validate_EmptyCustomRulePattern(t *testing.T) {
	config := DefaultConfig()
	config.CustomRules = []CustomRule{{ID: "test-rule", Pattern: ""}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has empty pattern")
}

func Test_Config_Validate_InvalidCustomRuleSeverity(t *testing.T) {
	config := DefaultConfig()
	config.CustomRules = []CustomRule{{ID: "test-rule", Pattern: "test", Severity: "invalid"}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity for custom-rule")
}

func Test_Config_Validate_InvalidCustomRulePattern(t *testing.T) {
	config := DefaultConfig()
	config.CustomRules = []CustomRule{{ID: "test-rule", Pattern: "[invalid(regex", Severity: SeverityMedium}}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern for custom-rule")
}

func Test_Config_GetRuleByID(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{
		{ID: "rule-1", Enabled: true},
		{ID: "rule-2", Enabled: false},
	}

	rule := config.GetRuleByID("rule-1")
	require.NotNil(t, rule)
	assert.Equal(t, "rule-1", rule.ID)
	assert.True(t, rule.Enabled)

	rule = config.GetRuleByID("rule-2")
	require.NotNil(t, rule)
	assert.False(t, rule.Enabled)

	rule = config.GetRuleByID("non-existent")
	assert.Nil(t, rule)
}

func Test_Config_GetCustomRuleByID(t *testing.T) {
	config := DefaultConfig()
	config.CustomRules = []CustomRule{
		{ID: "custom-1", Pattern: "pattern1"},
		{ID: "custom-2", Pattern: "pattern2"},
	}

	rule := config.GetCustomRuleByID("custom-1")
	require.NotNil(t, rule)
	assert.Equal(t, "pattern1", rule.Pattern)

	rule = config.GetCustomRuleByID("non-existent")
	assert.Nil(t, rule)
}

func Test_Config_GetScopeForPath(t *testing.T) {
	config := DefaultConfig()
	config.Scopes = []Scope{
		{Path: "agents/**", Severity: SeverityHigh},
		{Path: "docs/**", Severity: SeverityLow},
	}

	scope := config.GetScopeForPath("agents/test.md")
	require.NotNil(t, scope)
	assert.Equal(t, SeverityHigh, scope.Severity)

	scope = config.GetScopeForPath("docs/readme.md")
	require.NotNil(t, scope)
	assert.Equal(t, SeverityLow, scope.Severity)

	scope = config.GetScopeForPath("other/file.md")
	assert.Nil(t, scope)
}
