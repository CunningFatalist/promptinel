package promptinel

import (
	internalconfig "github.com/CunningFatalist/promptinel/internal/config"
	internalfinding "github.com/CunningFatalist/promptinel/internal/finding"
)

// Severity represents the severity level of a finding or rule.
type Severity string

const (
	// SeverityLow indicates an informational or low-impact finding.
	SeverityLow Severity = Severity(internalconfig.SeverityLow)
	// SeverityMedium indicates a finding that should be reviewed.
	SeverityMedium Severity = Severity(internalconfig.SeverityMedium)
	// SeverityHigh indicates a finding that should fail policy checks.
	SeverityHigh Severity = Severity(internalconfig.SeverityHigh)
)

// TrustLevel represents the trust level of an input source.
type TrustLevel string

const (
	// TrustLevelTrusted indicates trusted content.
	TrustLevelTrusted TrustLevel = TrustLevel(internalconfig.TrustLevelTrusted)
	// TrustLevelUntrusted indicates untrusted content.
	TrustLevelUntrusted TrustLevel = TrustLevel(internalconfig.TrustLevelUntrusted)
	// TrustLevelTainted indicates tainted content.
	TrustLevelTainted TrustLevel = TrustLevel(internalconfig.TrustLevelTainted)
)

const (
	// OversizedFileSkipID identifies findings for content skipped due to size limits.
	OversizedFileSkipID = internalfinding.OversizedFileSkipID
	// UnreadableFileSkipID identifies findings for file read or metadata failures.
	UnreadableFileSkipID = internalfinding.UnreadableFileSkipID
)

// Policy defines enforcement behavior for findings.
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

// Filters defines include and exclude globs for file selection.
type Filters struct {
	Include []string `mapstructure:"include"`
	Exclude []string `mapstructure:"exclude"`
}

// Scope defines severity adjustments based on file path patterns.
type Scope struct {
	Path     string   `mapstructure:"path"`
	Severity Severity `mapstructure:"severity"`
	Rules    []Rule   `mapstructure:"rules"`
}

// Rule defines a built-in rule configuration override.
type Rule struct {
	ID       string   `mapstructure:"id"`
	Enabled  *bool    `mapstructure:"enabled"`
	Severity Severity `mapstructure:"severity"`
}

// CustomRule defines a regex-based custom rule.
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
	Filters     Filters      `mapstructure:"filters"`
	Scopes      []Scope      `mapstructure:"scopes"`
	Rules       []Rule       `mapstructure:"rules"`
	CustomRules []CustomRule `mapstructure:"custom-rules"`
}

// Validate checks that the configuration is internally consistent.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	internalCfg := toInternalConfig(c)
	return internalCfg.Validate()
}

// Position describes where a finding occurred in the scanned content.
type Position struct {
	Line   int
	Column int
}

// Finding is a raw scanner finding.
type Finding struct {
	Path     string
	ID       string
	Severity Severity
	Message  string
	Position Position
	DocsURL  string
}

// Document is an in-memory scan target.
type Document struct {
	Path         string
	AbsolutePath string
	Content      string
}

func newConfigFromInternal(src *internalconfig.Config) *Config {
	if src == nil {
		return nil
	}

	cfg := &Config{
		Policy: Policy{
			FailOn: Severity(src.Policy.FailOn),
			WarnOn: Severity(src.Policy.WarnOn),
		},
		Environment: Environment{
			CanExecuteShell:     src.Environment.CanExecuteShell,
			CanAccessFilesystem: src.Environment.CanAccessFilesystem,
			CanAccessNetwork:    src.Environment.CanAccessNetwork,
			HasSecrets:          src.Environment.HasSecrets,
		},
		Trust: Trust{
			LocalFiles:            TrustLevel(src.Trust.LocalFiles),
			RemoteIncludes:        TrustLevel(src.Trust.RemoteIncludes),
			UserInputPlaceholders: TrustLevel(src.Trust.UserInputPlaceholders),
		},
		Limits: Limits{
			MaxFileSizeBytes: src.Limits.MaxFileSizeBytes,
		},
		Filters: Filters{
			Include: append([]string(nil), src.Filters.Include...),
			Exclude: append([]string(nil), src.Filters.Exclude...),
		},
		Rules:       make([]Rule, 0, len(src.Rules)),
		CustomRules: make([]CustomRule, 0, len(src.CustomRules)),
		Scopes:      make([]Scope, 0, len(src.Scopes)),
	}

	for _, rule := range src.Rules {
		cfg.Rules = append(cfg.Rules, newRuleFromInternal(rule))
	}
	for _, rule := range src.CustomRules {
		cfg.CustomRules = append(cfg.CustomRules, CustomRule{
			ID:       rule.ID,
			Pattern:  rule.Pattern,
			Severity: Severity(rule.Severity),
			Message:  rule.Message,
		})
	}
	for _, scope := range src.Scopes {
		converted := Scope{
			Path:     scope.Path,
			Severity: Severity(scope.Severity),
			Rules:    make([]Rule, 0, len(scope.Rules)),
		}
		for _, rule := range scope.Rules {
			converted.Rules = append(converted.Rules, newRuleFromInternal(rule))
		}
		cfg.Scopes = append(cfg.Scopes, converted)
	}

	return cfg
}

func newRuleFromInternal(src internalconfig.Rule) Rule {
	rule := Rule{
		ID:       src.ID,
		Severity: Severity(src.Severity),
	}
	if src.Enabled != nil {
		enabled := *src.Enabled
		rule.Enabled = &enabled
	}
	return rule
}

func toInternalConfig(src *Config) *internalconfig.Config {
	if src == nil {
		return nil
	}

	cfg := &internalconfig.Config{
		Policy: internalconfig.Policy{
			FailOn: internalconfig.Severity(src.Policy.FailOn),
			WarnOn: internalconfig.Severity(src.Policy.WarnOn),
		},
		Environment: internalconfig.Environment{
			CanExecuteShell:     src.Environment.CanExecuteShell,
			CanAccessFilesystem: src.Environment.CanAccessFilesystem,
			CanAccessNetwork:    src.Environment.CanAccessNetwork,
			HasSecrets:          src.Environment.HasSecrets,
		},
		Trust: internalconfig.Trust{
			LocalFiles:            internalconfig.TrustLevel(src.Trust.LocalFiles),
			RemoteIncludes:        internalconfig.TrustLevel(src.Trust.RemoteIncludes),
			UserInputPlaceholders: internalconfig.TrustLevel(src.Trust.UserInputPlaceholders),
		},
		Limits: internalconfig.Limits{
			MaxFileSizeBytes: src.Limits.MaxFileSizeBytes,
		},
		Filters: internalconfig.Filters{
			Include: append([]string(nil), src.Filters.Include...),
			Exclude: append([]string(nil), src.Filters.Exclude...),
		},
		Rules:       make([]internalconfig.Rule, 0, len(src.Rules)),
		CustomRules: make([]internalconfig.CustomRule, 0, len(src.CustomRules)),
		Scopes:      make([]internalconfig.Scope, 0, len(src.Scopes)),
	}

	for _, rule := range src.Rules {
		cfg.Rules = append(cfg.Rules, toInternalRule(rule))
	}
	for _, rule := range src.CustomRules {
		cfg.CustomRules = append(cfg.CustomRules, internalconfig.CustomRule{
			ID:       rule.ID,
			Pattern:  rule.Pattern,
			Severity: internalconfig.Severity(rule.Severity),
			Message:  rule.Message,
		})
	}
	for _, scope := range src.Scopes {
		converted := internalconfig.Scope{
			Path:     scope.Path,
			Severity: internalconfig.Severity(scope.Severity),
			Rules:    make([]internalconfig.Rule, 0, len(scope.Rules)),
		}
		for _, rule := range scope.Rules {
			converted.Rules = append(converted.Rules, toInternalRule(rule))
		}
		cfg.Scopes = append(cfg.Scopes, converted)
	}

	return cfg
}

func toInternalRule(src Rule) internalconfig.Rule {
	rule := internalconfig.Rule{
		ID:       src.ID,
		Severity: internalconfig.Severity(src.Severity),
	}
	if src.Enabled != nil {
		enabled := *src.Enabled
		rule.Enabled = &enabled
	}
	return rule
}
