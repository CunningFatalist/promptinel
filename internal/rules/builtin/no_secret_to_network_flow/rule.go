package nosecrettonetworkflow

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-secret-to-network-flow"
	name        = "No Secret To Network Flow"
	summary     = "Detects secret-source to outbound-network exfiltration chains"
	description = "The combination of secret references, exfiltration language, and outbound network sinks suggests a high-risk exfiltration flow."
)

// Rule detects secret-to-network exfiltration chains across the full analyzed document.
type Rule struct{}

// New returns the no-secret-to-network-flow rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-secret-to-network-flow rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-secret-to-network-flow rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects cross-segment secret-source to outbound-network exfiltration chains.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.HasSecrets() {
		return nil
	}

	var firstSecret *rules.Token
	hasAction := false
	hasSink := false

	for _, tokens := range doc.TokensBySegment {
		for i := range tokens {
			token := tokens[i]
			lower := strings.ToLower(token.Value)

			if firstSecret == nil && isSecretSignal(token, lower) {
				firstSecret = &tokens[i]
			}

			if _, ok := signals.ExfiltrationActionSignals[lower]; ok {
				hasAction = true
			}

			if token.Type == lexer.TokenURL {
				hasSink = true
			}
			if token.Type == lexer.TokenShellCommand {
				if _, ok := signals.OutboundSinkCommands[lower]; ok {
					hasSink = true
				}
			}
		}
	}

	if firstSecret == nil || !hasAction || !hasSink {
		return nil
	}

	return []rules.Finding{{
		Message:  "Potential secret-to-network exfiltration flow detected",
		Position: firstSecret.Position,
	}}
}

func isSecretSignal(token rules.Token, lower string) bool {
	for _, signal := range signals.SecretSignals {
		if strings.Contains(lower, signal) {
			return true
		}
	}

	return token.Type == lexer.TokenPath && (strings.Contains(lower, "credentials") || strings.Contains(lower, "secret") || strings.Contains(lower, "passwd") || strings.Contains(lower, "id_rsa"))
}
