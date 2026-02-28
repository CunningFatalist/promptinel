package nooverridecapabilityflow

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-override-capability-flow"
	name        = "No Override Capability Flow"
	summary     = "Detects prompt overrides combined with actionable capability signals"
	description = "When instruction-override phrases are combined with shell, network, or sensitive file operations, risk increases significantly."
)

// Rule detects override-to-capability escalation chains.
type Rule struct{}

// New returns the no-override-capability-flow rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-override-capability-flow rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-override-capability-flow rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects when override language co-occurs with shell/network/sensitive capability signals.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	contentLower := strings.ToLower(doc.Document.Content)
	overrideOffset := -1
	for _, signal := range signals.OverridePhrases {
		offset := strings.Index(contentLower, signal)
		if offset == -1 {
			continue
		}
		if overrideOffset == -1 || offset < overrideOffset {
			overrideOffset = offset
		}
	}
	if overrideOffset == -1 {
		return nil
	}

	hasNetworkAction := false
	hasShellAction := false
	hasFilesystemAction := false
	hasSecretAction := false
	for _, tokens := range doc.TokensBySegment {
		for _, token := range tokens {
			if token.Type == lexer.TokenURL {
				hasNetworkAction = true
			}
			if token.Type == lexer.TokenShellCommand {
				hasShellAction = true
			}

			lower := strings.ToLower(token.Value)
			matchesFilesystemSignal := false
			for _, signal := range signals.FilesystemCapabilitySignals {
				if strings.Contains(lower, signal) {
					hasFilesystemAction = true
					matchesFilesystemSignal = true
				}
			}

			for _, signal := range signals.CapabilitySignals {
				if strings.Contains(lower, signal) {
					switch signal {
					case "metadata", "169.254.169.254":
						hasNetworkAction = true
					case "token", "password":
						if !matchesFilesystemSignal {
							hasSecretAction = true
						}
					}
				}
			}
		}
	}

	// Some capability snippets can be split across token boundaries; check raw content too.
	for _, signal := range signals.FilesystemCapabilitySignals {
		if strings.Contains(contentLower, signal) {
			hasFilesystemAction = true
			break
		}
	}

	if !capabilityAvailableInContext(ctx, hasNetworkAction, hasShellAction, hasFilesystemAction, hasSecretAction) {
		return nil
	}

	return []rules.Finding{{
		Message:  "Prompt override combined with capability-oriented actions detected",
		Position: rules.PositionFromByteOffset(doc.Document.Content, overrideOffset),
	}}
}

func capabilityAvailableInContext(ctx rules.Context, hasNetwork bool, hasShell bool, hasFilesystem bool, hasSecrets bool) bool {
	return (hasNetwork && ctx.CanAccessNetwork()) ||
		(hasShell && ctx.CanExecuteShell()) ||
		(hasFilesystem && ctx.CanAccessFilesystem()) ||
		(hasSecrets && ctx.HasSecrets())
}
