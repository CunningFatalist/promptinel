package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

// Severity levels for findings and rules.
const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Trust levels for different input sources.
const (
	TrustLevelTrusted   TrustLevel = "trusted"
	TrustLevelUntrusted TrustLevel = "untrusted"
	TrustLevelTainted   TrustLevel = "tainted"
)

// Config file constants.
const (
	DefaultConfigName = ".promptinel"
	ConfigType        = "yaml"
)

// Severity represents the severity level of a finding or rule.
type Severity string

// TrustLevel represents the trust level of an input source.
type TrustLevel string

// Policy defines the enforcement behavior for findings.
type Policy struct {
	FailOn   Severity `mapstructure:"fail-on"`
	WarnOn   Severity `mapstructure:"warn-on"`
	IgnoreOn Severity `mapstructure:"ignore-on"`
}

// Environment defines the capabilities of the agent runtime.
type Environment struct {
	CanExecuteShell     bool `mapstructure:"can_execute_shell"`
	CanAccessFilesystem bool `mapstructure:"can_access_filesystem"`
	CanAccessNetwork    bool `mapstructure:"can_access_network"`
	HasSecrets          bool `mapstructure:"has_secrets"`
}

// Trust defines the trust model for different input sources.
type Trust struct {
	LocalFiles            TrustLevel `mapstructure:"local-files"`
	RemoteIncludes        TrustLevel `mapstructure:"remote-includes"`
	UserInputPlaceholders TrustLevel `mapstructure:"user-input-placeholders"`
}

// Scope defines severity adjustments based on file path patterns.
type Scope struct {
	Path     string   `mapstructure:"path"`
	Severity Severity `mapstructure:"severity"`
}

// Rule defines a built-in security rule configuration.
type Rule struct {
	ID       string   `mapstructure:"id"`
	Enabled  bool     `mapstructure:"enabled"`
	Severity Severity `mapstructure:"severity"`
}

// CustomRule defines a user-defined regex-based rule.
type CustomRule struct {
	ID       string   `mapstructure:"id"`
	Pattern  string   `mapstructure:"pattern"`
	Severity Severity `mapstructure:"severity"`
	Message  string   `mapstructure:"message"`
}

// Config represents the complete Promptinel configuration.
type Config struct {
	Policy      Policy       `mapstructure:"policy"`
	Environment Environment  `mapstructure:"environment"`
	Trust       Trust        `mapstructure:"trust"`
	Scopes      []Scope      `mapstructure:"scopes"`
	Rules       []Rule       `mapstructure:"rules"`
	CustomRules []CustomRule `mapstructure:"custom-rules"`
}

// DefaultConfig returns a Config with sensible and secure default values.
func DefaultConfig() *Config {
	return &Config{
		Policy: Policy{
			FailOn:   SeverityHigh,
			WarnOn:   SeverityMedium,
			IgnoreOn: SeverityLow,
		},
		Environment: Environment{
			CanExecuteShell:     true,
			CanAccessFilesystem: true,
			CanAccessNetwork:    true,
			HasSecrets:          true,
		},
		Trust: Trust{
			LocalFiles:            TrustLevelTrusted,
			RemoteIncludes:        TrustLevelUntrusted,
			UserInputPlaceholders: TrustLevelTainted,
		},
		Scopes:      []Scope{},
		Rules:       []Rule{},
		CustomRules: []CustomRule{},
	}
}

// Load reads configuration from the specified file path.
// If configFile is empty, it searches for .promptinel.yaml in the current directory and $HOME.
// Returns default config if no config file is found.
func Load(configFile string) (*Config, error) {
	config := DefaultConfig()
	v := viper.New()

	setDefaults(v, config)

	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		v.SetConfigName(DefaultConfigName)
		v.SetConfigType(ConfigType)
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return config, nil
		}
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// LoadFromPath loads configuration from a file or directory path.
// If path is a directory, it looks for .promptinel.yaml inside it.
func LoadFromPath(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("error resolving path: %w", err)
	}

	if info, err := os.Stat(absPath); err == nil && info.IsDir() {
		absPath = filepath.Join(absPath, DefaultConfigName+"."+ConfigType)
	}

	return Load(absPath)
}

// setDefaults applies default values to the viper instance.
func setDefaults(v *viper.Viper, config *Config) {
	v.SetDefault("policy.fail-on", config.Policy.FailOn)
	v.SetDefault("policy.warn-on", config.Policy.WarnOn)
	v.SetDefault("policy.ignore-on", config.Policy.IgnoreOn)

	v.SetDefault("environment.can_execute_shell", config.Environment.CanExecuteShell)
	v.SetDefault("environment.can_access_filesystem", config.Environment.CanAccessFilesystem)
	v.SetDefault("environment.can_access_network", config.Environment.CanAccessNetwork)
	v.SetDefault("environment.has_secrets", config.Environment.HasSecrets)

	v.SetDefault("trust.local-files", config.Trust.LocalFiles)
	v.SetDefault("trust.remote-includes", config.Trust.RemoteIncludes)
	v.SetDefault("trust.user-input-placeholders", config.Trust.UserInputPlaceholders)

	v.SetDefault("scopes", config.Scopes)
	v.SetDefault("rules", config.Rules)
	v.SetDefault("custom-rules", config.CustomRules)
}

// IsValid returns true if the severity is a valid value.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh:
		return true
	default:
		return false
	}
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// MarshalYAML implements yaml.Marshaler for Severity.
func (s Severity) MarshalYAML() (interface{}, error) {
	return string(s), nil
}

// UnmarshalYAML implements yaml.Unmarshaler for Severity.
func (s *Severity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	*s = Severity(strings.ToLower(str))
	return nil
}

// IsValid returns true if the trust level is a valid value.
func (t TrustLevel) IsValid() bool {
	switch t {
	case TrustLevelTrusted, TrustLevelUntrusted, TrustLevelTainted:
		return true
	default:
		return false
	}
}

// String returns the string representation of the trust level.
func (t TrustLevel) String() string {
	return string(t)
}

// MarshalYAML implements yaml.Marshaler for TrustLevel.
func (t TrustLevel) MarshalYAML() (interface{}, error) {
	return string(t), nil
}

// UnmarshalYAML implements yaml.Unmarshaler for TrustLevel.
func (t *TrustLevel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	*t = TrustLevel(strings.ToLower(str))
	return nil
}

// Validate checks that all configuration values are valid.
func (c *Config) Validate() error {
	if !c.Policy.FailOn.IsValid() {
		return fmt.Errorf("invalid policy.fail-on severity: %s", c.Policy.FailOn)
	}
	if !c.Policy.WarnOn.IsValid() {
		return fmt.Errorf("invalid policy.warn-on severity: %s", c.Policy.WarnOn)
	}
	if !c.Policy.IgnoreOn.IsValid() {
		return fmt.Errorf("invalid policy.ignore-on severity: %s", c.Policy.IgnoreOn)
	}

	if !c.Trust.LocalFiles.IsValid() {
		return fmt.Errorf("invalid trust.local-files level: %s", c.Trust.LocalFiles)
	}
	if !c.Trust.RemoteIncludes.IsValid() {
		return fmt.Errorf("invalid trust.remote-includes level: %s", c.Trust.RemoteIncludes)
	}
	if !c.Trust.UserInputPlaceholders.IsValid() {
		return fmt.Errorf("invalid trust.user-input-placeholders level: %s", c.Trust.UserInputPlaceholders)
	}

	for i, scope := range c.Scopes {
		if !scope.Severity.IsValid() {
			return fmt.Errorf("invalid severity for scope[%d]: %s", i, scope.Severity)
		}
		if _, err := filepath.Match(scope.Path, ""); err != nil {
			return fmt.Errorf("invalid glob pattern for scope[%d]: %s", i, scope.Path)
		}
	}

	for i, rule := range c.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule[%d] has empty id", i)
		}
		if rule.Severity != "" && !rule.Severity.IsValid() {
			return fmt.Errorf("invalid severity for rule[%d]: %s", i, rule.Severity)
		}
	}

	for i, rule := range c.CustomRules {
		if rule.ID == "" {
			return fmt.Errorf("custom-rule[%d] has empty id", i)
		}
		if rule.Pattern == "" {
			return fmt.Errorf("custom-rule[%d] has empty pattern", i)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern for custom-rule[%d]: %w", i, err)
		}
		if !rule.Severity.IsValid() {
			return fmt.Errorf("invalid severity for custom-rule[%d]: %s", i, rule.Severity)
		}
	}

	return nil
}

// GetRuleByID returns the rule with the given ID, or nil if not found.
func (c *Config) GetRuleByID(id string) *Rule {
	for i := range c.Rules {
		if c.Rules[i].ID == id {
			return &c.Rules[i]
		}
	}
	return nil
}

// GetCustomRuleByID returns the custom rule with the given ID, or nil if not found.
func (c *Config) GetCustomRuleByID(id string) *CustomRule {
	for i := range c.CustomRules {
		if c.CustomRules[i].ID == id {
			return &c.CustomRules[i]
		}
	}
	return nil
}

// GetScopeForPath returns the scope matching the given path, or nil if no match.
func (c *Config) GetScopeForPath(path string) *Scope {
	for i := range c.Scopes {
		matched, err := filepath.Match(c.Scopes[i].Path, path)
		if err == nil && matched {
			return &c.Scopes[i]
		}
	}
	return nil
}
