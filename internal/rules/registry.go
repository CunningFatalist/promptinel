package rules

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/CunningFatalist/promptinel/internal/config"
)

// Registry contains all built-in rules.
type Registry struct {
	ordered []ruleEntry
	byID    map[string]ruleEntry
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		ordered: make([]ruleEntry, 0),
		byID:    make(map[string]ruleEntry),
	}
}

// Register adds a rule implementation to the registry.
func (r *Registry) Register(rule Rule) error {
	if r == nil {
		return fmt.Errorf("registry is nil")
	}

	if isNilRule(rule) {
		return fmt.Errorf("rule is nil")
	}

	meta := rule.Metadata()
	if meta.ID == "" {
		return fmt.Errorf("rule has empty id")
	}
	if !meta.DefaultSeverity.IsValid() {
		return fmt.Errorf("rule %q has invalid default severity %q", meta.ID, meta.DefaultSeverity)
	}
	if !supportsAtLeastOnePhase(rule) {
		return fmt.Errorf("rule %q has no phase checks", meta.ID)
	}
	if _, exists := r.byID[meta.ID]; exists {
		return fmt.Errorf("duplicate rule id %q", meta.ID)
	}

	entry := ruleEntry{metadata: meta, rule: rule}
	r.byID[meta.ID] = entry
	r.ordered = append(r.ordered, entry)
	sort.SliceStable(r.ordered, func(i, j int) bool {
		return r.ordered[i].metadata.ID < r.ordered[j].metadata.ID
	})

	return nil
}

// List returns metadata for all registered rules.
func (r *Registry) List() []Metadata {
	if r == nil {
		return nil
	}
	metadata := make([]Metadata, 0, len(r.ordered))
	for _, entry := range r.ordered {
		metadata = append(metadata, entry.metadata)
	}
	return metadata
}

// Describe returns metadata for a single rule by ID.
func (r *Registry) Describe(id string) (Metadata, bool) {
	if r == nil {
		return Metadata{}, false
	}
	entry, ok := r.byID[id]
	if !ok {
		return Metadata{}, false
	}
	return entry.metadata, true
}

// Compile resolves enabled rules and effective severities from config.
func (r *Registry) Compile(cfg *config.Config) ([]CompiledRule, error) {
	if r == nil {
		return nil, fmt.Errorf("registry is nil")
	}

	compiled := make([]CompiledRule, 0, len(r.ordered))
	usedIDs := make(map[string]struct{}, len(r.ordered))

	for _, entry := range r.ordered {
		meta := entry.metadata
		enabled := true
		severity := meta.DefaultSeverity

		if cfg != nil {
			if configuredRule := cfg.GetRuleByID(meta.ID); configuredRule != nil {
				if configuredRule.Enabled != nil {
					enabled = *configuredRule.Enabled
				}
				if configuredRule.Severity != "" {
					severity = configuredRule.Severity
				}
			}
		}

		if !enabled {
			continue
		}
		if !severity.IsValid() {
			return nil, fmt.Errorf("rule %q has invalid resolved severity %q", meta.ID, severity)
		}

		compiledRule := compileRule(entry.rule, meta.ID, severity)
		compiled = append(compiled, compiledRule)
		usedIDs[meta.ID] = struct{}{}
	}

	if cfg != nil {
		for _, customCfg := range cfg.CustomRules {
			customRule, err := compileCustomRule(customCfg)
			if err != nil {
				return nil, err
			}
			meta := customRule.Metadata()
			if meta.ID == "" {
				return nil, fmt.Errorf("custom rule has empty id")
			}
			if !meta.DefaultSeverity.IsValid() {
				return nil, fmt.Errorf("custom rule %q has invalid severity %q", meta.ID, meta.DefaultSeverity)
			}
			if _, exists := usedIDs[meta.ID]; exists {
				return nil, fmt.Errorf("duplicate rule id %q", meta.ID)
			}
			compiled = append(compiled, compileRule(customRule, meta.ID, meta.DefaultSeverity))
			usedIDs[meta.ID] = struct{}{}
		}
	}

	return compiled, nil
}

func compileRule(rule Rule, id string, severity config.Severity) CompiledRule {
	checks := extractPhaseChecks(rule)

	return CompiledRule{
		ID:            id,
		Severity:      severity,
		checkDocument: checks.document,
		checkSegment:  checks.segment,
		checkTokens:   checks.tokens,
		checkFlow:     checks.flow,
	}
}

func supportsAtLeastOnePhase(rule Rule) bool {
	return extractPhaseChecks(rule).hasAny()
}

func isNilRule(rule Rule) bool {
	if rule == nil {
		return true
	}

	rv := reflect.ValueOf(rule)

	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

type phaseChecks struct {
	document func(Context, DocumentView) []Finding
	segment  func(Context, Segment) []Finding
	tokens   func(Context, Segment, []Token) []Finding
	flow     func(Context, AnalyzedDocument) []Finding
}

func (p phaseChecks) hasAny() bool {
	return p.document != nil || p.segment != nil || p.tokens != nil || p.flow != nil
}

func extractPhaseChecks(rule Rule) phaseChecks {
	var checks phaseChecks

	if documentRule, ok := rule.(DocumentRule); ok {
		checks.document = documentRule.CheckDocument
	}
	if segmentRule, ok := rule.(SegmentRule); ok {
		checks.segment = segmentRule.CheckSegment
	}
	if tokenRule, ok := rule.(TokenRule); ok {
		checks.tokens = tokenRule.CheckTokens
	}
	if flowRule, ok := rule.(FlowRule); ok {
		checks.flow = flowRule.CheckFlow
	}

	return checks
}
