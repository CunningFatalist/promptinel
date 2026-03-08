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

	maxTriadTokenWindowTrusted   = 26
	maxTriadTokenWindowUntrusted = 44
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

	sources := make([]tokenStage, 0)
	actions := make([]int, 0)
	sinks := make([]int, 0)
	tokensByIndex := make([]rules.Token, 0)
	globalIndex := 0
	for _, tokens := range doc.TokensBySegment {
		for i := range tokens {
			token := tokens[i]
			lower := strings.ToLower(token.Value)
			tokensByIndex = append(tokensByIndex, token)

			if isSecretSignal(token, lower) {
				sources = append(sources, tokenStage{
					Index:    globalIndex,
					Start:    token.Start,
					End:      token.End,
					Position: token.Position,
				})
			}

			if isExfiltrationActionSignal(token, lower) {
				actions = append(actions, globalIndex)
			}

			if isOutboundSinkSignal(token, lower) {
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
			if actionIndex < source.Index {
				continue
			}
			for _, sinkIndex := range sinks {
				if sinkIndex < actionIndex {
					continue
				}

				maxWindow := maxTriadTokenWindowTrusted
				if ctx.IsUntrustedRange(source.Start, tokensByIndex[sinkIndex].End) {
					maxWindow = maxTriadTokenWindowUntrusted
				}
				if actionIndex-source.Index > maxWindow || sinkIndex-source.Index > maxWindow {
					continue
				}
				return []rules.Finding{{
					Message:  "Potential secret-to-network exfiltration flow detected",
					Position: source.Position,
				}}
			}
		}
	}

	return nil
}

type tokenStage struct {
	Index    int
	Start    int
	End      int
	Position rules.Position
}

func isExfiltrationActionSignal(token rules.Token, lower string) bool {
	if _, ok := signals.ExfiltrationActionSignals[lower]; ok {
		return true
	}
	if token.Type == lexer.TokenShellCommand {
		if _, ok := signals.ExfiltrationCommands[lower]; ok {
			return true
		}
	}
	return lower == "webhook" || lower == "requestbin"
}

func isOutboundSinkSignal(token rules.Token, lower string) bool {
	if token.Type == lexer.TokenURL {
		return true
	}
	if _, ok := signals.DNSSinkCommands[lower]; ok {
		return true
	}
	if token.Type == lexer.TokenShellCommand {
		if _, ok := signals.OutboundSinkCommands[lower]; ok {
			return true
		}
	}
	for _, snippet := range signals.OutboundSinkSnippets {
		if strings.Contains(lower, snippet) {
			return true
		}
	}
	return false
}

func containsAnySnippet(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}
	return false
}

func isSecretPathSignal(lower string) bool {
	return containsAnySnippet(lower, signals.SensitivePathSnippets)
}

func isSecretSignal(token rules.Token, lower string) bool {
	for _, signal := range signals.SecretSignals {
		if strings.Contains(lower, signal) {
			return true
		}
	}

	if token.Type == lexer.TokenPath && (strings.Contains(lower, "credentials") || strings.Contains(lower, "secret") || strings.Contains(lower, "passwd") || strings.Contains(lower, "id_rsa")) {
		return true
	}
	if token.Type == lexer.TokenWord && (lower == "api" || lower == "access" || lower == "secret" || lower == "token") {
		return true
	}
	return isSecretPathSignal(lower)
}
