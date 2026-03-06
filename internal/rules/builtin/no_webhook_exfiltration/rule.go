package nowebhookexfiltration

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-webhook-exfiltration"
	name        = "No Webhook Exfiltration"
	summary     = "Detects secret/file exfiltration chains targeting webhook sinks"
	description = "Webhook and request-bin sinks combined with sensitive data signals and transfer actions indicate likely exfiltration behavior."

	maxWebhookChainDistance = 30
)

// Rule detects webhook-targeted exfiltration chains.
type Rule struct{}

// New returns the no-webhook-exfiltration rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-webhook-exfiltration rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-webhook-exfiltration rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects source->action->webhook chains across tokens and segments.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessNetwork() || (!ctx.HasSecrets() && !ctx.CanAccessFilesystem()) {
		return nil
	}

	sources := make([]indexedPosition, 0)
	actions := make([]int, 0)
	sinks := make([]int, 0)
	globalIndex := 0

	for _, tokens := range doc.TokensBySegment {
		for i := range tokens {
			token := tokens[i]
			lower := strings.ToLower(token.Value)

			if isSourceSignal(token, lower) {
				sources = append(sources, indexedPosition{Index: globalIndex, Position: token.Position})
			}
			if isActionSignal(lower) {
				actions = append(actions, globalIndex)
			}
			if isWebhookSinkSignal(token, lower) {
				sinks = append(sinks, globalIndex)
			}

			globalIndex++
		}
	}

	if len(sources) == 0 || len(actions) == 0 || len(sinks) == 0 {
		return nil
	}

	for _, source := range sources {
		for _, actionIndex := range actions {
			if actionIndex < source.Index || actionIndex-source.Index > maxWebhookChainDistance {
				continue
			}
			for _, sinkIndex := range sinks {
				if sinkIndex < actionIndex || sinkIndex-source.Index > maxWebhookChainDistance {
					continue
				}
				return []rules.Finding{{
					Message:  "Webhook exfiltration pattern detected",
					Position: source.Position,
				}}
			}
		}
	}

	return nil
}

type indexedPosition struct {
	Index    int
	Position rules.Position
}

func isSourceSignal(token rules.Token, lower string) bool {
	for _, signal := range signals.SecretSignals {
		if strings.Contains(lower, signal) {
			return true
		}
	}
	for _, snippet := range signals.SensitivePathSnippets {
		if strings.Contains(lower, snippet) {
			return true
		}
	}
	return token.Type == lexer.TokenPath && (strings.Contains(lower, "secret") || strings.Contains(lower, "credential") || strings.Contains(lower, "token"))
}

func isActionSignal(lower string) bool {
	if _, ok := signals.ExfiltrationActionSignals[lower]; ok {
		return true
	}
	return lower == "post" || lower == "send" || lower == "upload" || lower == "forward"
}

func isWebhookSinkSignal(token rules.Token, lower string) bool {
	if token.Type == lexer.TokenURL {
		for _, sink := range signals.WebhookSinkSnippets {
			if strings.Contains(lower, sink) {
				return true
			}
		}
	}
	for _, sink := range signals.WebhookSinkSnippets {
		if strings.Contains(lower, sink) {
			return true
		}
	}
	return false
}
