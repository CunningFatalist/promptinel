package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/pathmatch"
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
	DefaultConfigName             = ".promptinel"
	ConfigType                    = "yaml"
	DefaultMaxFileSizeBytes int64 = 5 * 1024 * 1024
)

// Severity represents the severity level of a finding or rule.
type Severity string

// TrustLevel represents the trust level of an input source.
type TrustLevel string

// Policy defines the enforcement behavior for findings.
type Policy struct {
	FailOn Severity `mapstructure:"fail-on"`
	WarnOn Severity `mapstructure:"warn-on"`
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

// Limits defines scanner guardrails.
type Limits struct {
	MaxFileSizeBytes int64 `mapstructure:"max_file_size_bytes"`
}

// Scope defines severity adjustments based on file path patterns.
type Scope struct {
	Path     string   `mapstructure:"path"`
	Severity Severity `mapstructure:"severity"`
}

// Rule defines a built-in security rule configuration.
type Rule struct {
	ID       string   `mapstructure:"id"`
	Enabled  *bool    `mapstructure:"enabled"`
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
	Limits      Limits       `mapstructure:"limits"`
	Scopes      []Scope      `mapstructure:"scopes"`
	Rules       []Rule       `mapstructure:"rules"`
	CustomRules []CustomRule `mapstructure:"custom-rules"`
}

// LoadOptions controls config loading behavior.
type LoadOptions struct {
	Discover bool
}

// DefaultConfig returns a Config with sensible and secure default values.
func DefaultConfig() *Config {
	return &Config{
		Policy: Policy{
			FailOn: SeverityHigh,
			WarnOn: SeverityMedium,
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
		Limits: Limits{
			MaxFileSizeBytes: DefaultMaxFileSizeBytes,
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
	return LoadWithOptions(configFile, LoadOptions{Discover: true})
}

// LoadWithOptions reads configuration with explicit loading behavior.
// If configFile is empty and Discover is false, only secure defaults are used.
func LoadWithOptions(configFile string, options LoadOptions) (*Config, error) {
	cfg := DefaultConfig()
	v := viper.New()

	setDefaults(v, cfg)

	if configFile != "" {
		v.SetConfigFile(configFile)
	} else if options.Discover {
		v.SetConfigName(DefaultConfigName)
		v.SetConfigType(ConfigType)
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
	} else {
		return cfg, nil
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return cfg, nil
		}
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
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

	return LoadWithOptions(absPath, LoadOptions{Discover: true})
}

// setDefaults applies default values to the viper instance.
func setDefaults(v *viper.Viper, cfg *Config) {
	v.SetDefault("policy.fail-on", cfg.Policy.FailOn)
	v.SetDefault("policy.warn-on", cfg.Policy.WarnOn)

	v.SetDefault("environment.can_execute_shell", cfg.Environment.CanExecuteShell)
	v.SetDefault("environment.can_access_filesystem", cfg.Environment.CanAccessFilesystem)
	v.SetDefault("environment.can_access_network", cfg.Environment.CanAccessNetwork)
	v.SetDefault("environment.has_secrets", cfg.Environment.HasSecrets)

	v.SetDefault("trust.local-files", cfg.Trust.LocalFiles)
	v.SetDefault("trust.remote-includes", cfg.Trust.RemoteIncludes)
	v.SetDefault("trust.user-input-placeholders", cfg.Trust.UserInputPlaceholders)
	v.SetDefault("limits.max_file_size_bytes", cfg.Limits.MaxFileSizeBytes)

	v.SetDefault("scopes", cfg.Scopes)
	v.SetDefault("rules", cfg.Rules)
	v.SetDefault("custom-rules", cfg.CustomRules)
}

// IsValid returns true if the severity is a valid value.
func (s *Severity) IsValid() bool {
	if s == nil {
		return false
	}

	switch *s {
	case SeverityLow, SeverityMedium, SeverityHigh:
		return true
	default:
		return false
	}
}

// String returns the string representation of the severity.
func (s *Severity) String() string {
	if s == nil {
		return ""
	}

	return string(*s)
}

// MarshalYAML implements yaml.Marshaler for Severity.
func (s *Severity) MarshalYAML() (interface{}, error) {
	if s == nil {
		return "", nil
	}

	return string(*s), nil
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
func (t *TrustLevel) IsValid() bool {
	if t == nil {
		return false
	}

	switch *t {
	case TrustLevelTrusted, TrustLevelUntrusted, TrustLevelTainted:
		return true
	default:
		return false
	}
}

// String returns the string representation of the trust level.
func (t *TrustLevel) String() string {
	if t == nil {
		return ""
	}

	return string(*t)
}

// MarshalYAML implements yaml.Marshaler for TrustLevel.
func (t *TrustLevel) MarshalYAML() (interface{}, error) {
	if t == nil {
		return "", nil
	}

	return string(*t), nil
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
	if !SeverityAtLeast(c.Policy.FailOn, c.Policy.WarnOn) {
		return fmt.Errorf("invalid policy severity ordering: fail-on (%s) must be greater than or equal to warn-on (%s)", c.Policy.FailOn, c.Policy.WarnOn)
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
	if c.Limits.MaxFileSizeBytes <= 0 {
		return fmt.Errorf("invalid limits.max_file_size_bytes: must be greater than 0")
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
	if err := validateUniqueRuleIDs(c.Rules); err != nil {
		return err
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
	if err := validateUniqueCustomRuleIDs(c.CustomRules); err != nil {
		return err
	}

	return nil
}

func validateUniqueRuleIDs(rules []Rule) error {
	seenRuleIDs := make(map[string]int, len(rules))
	for i, rule := range rules {
		if previousIndex, exists := seenRuleIDs[rule.ID]; exists {
			return fmt.Errorf("duplicate rule id %q at rules[%d] (already defined at rules[%d])", rule.ID, i, previousIndex)
		}
		seenRuleIDs[rule.ID] = i
	}
	return nil
}

func validateUniqueCustomRuleIDs(customRules []CustomRule) error {
	seenRuleIDs := make(map[string]int, len(customRules))
	for i, customRule := range customRules {
		if previousIndex, exists := seenRuleIDs[customRule.ID]; exists {
			return fmt.Errorf("duplicate custom-rule id %q at custom-rules[%d] (already defined at custom-rules[%d])", customRule.ID, i, previousIndex)
		}
		seenRuleIDs[customRule.ID] = i
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
		if pathmatch.Match(c.Scopes[i].Path, path) {
			return &c.Scopes[i]
		}
	}
	return nil
}
