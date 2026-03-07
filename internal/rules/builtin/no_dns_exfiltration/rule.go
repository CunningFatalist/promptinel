package nodnsexfiltration

import (
	"strings"
	"unicode"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id           = "no-dns-exfiltration"
	name         = "No DNS Exfiltration"
	summary      = "Detects DNS-based exfiltration chains"
	description  = "DNS lookup utilities combined with secret sources and external domains strongly suggest DNS-based exfiltration behavior."
	maxDNSWindow = 24
)

// Rule detects DNS-based exfiltration chains.
type Rule struct{}

// New returns the no-dns-exfiltration rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-dns-exfiltration rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-dns-exfiltration rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects secret -> DNS lookup -> external domain chains.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.HasSecrets() {
		return nil
	}

	type sourceRef struct {
		index int
		pos   rules.Position
	}

	sources := make([]sourceRef, 0)
	actions := make([]int, 0)
	sinks := make([]int, 0)
	globalIndex := 0

	for _, tokens := range doc.TokensBySegment {
		for _, token := range tokens {
			lower := strings.ToLower(token.Value)
			if isSecretSignal(token, lower) {
				sources = append(sources, sourceRef{index: globalIndex, pos: token.Position})
			}
			if _, ok := signals.DNSSinkCommands[lower]; ok {
				actions = append(actions, globalIndex)
			}
			if isExternalDomainSignal(token, lower) {
				sinks = append(sinks, globalIndex)
			}
			globalIndex++
		}
	}

	for _, source := range sources {
		for _, action := range actions {
			if action < source.index || action-source.index > maxDNSWindow {
				continue
			}
			for _, sink := range sinks {
				if sink < action || sink-source.index > maxDNSWindow {
					continue
				}
				return []rules.Finding{{
					Message:  "Potential DNS exfiltration flow detected",
					Position: source.pos,
				}}
			}
		}
	}

	return nil
}

func isSecretSignal(token rules.Token, lower string) bool {
	for _, signal := range signals.SecretSignals {
		if strings.Contains(lower, signal) {
			return true
		}
	}
	return token.Type == lexer.TokenPath && (strings.Contains(lower, "credential") || strings.Contains(lower, "secret") || strings.Contains(lower, "token"))
}

func isExternalDomainSignal(token rules.Token, lower string) bool {
	if token.Type != lexer.TokenWord && token.Type != lexer.TokenURL {
		return false
	}
	if !strings.Contains(lower, ".") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	for _, suffix := range signals.DNSInternalDomainSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	if strings.HasPrefix(lower, "169.254.") || unicode.IsDigit(rune(lower[0])) {
		return false
	}
	parts := strings.Split(lower, ".")
	return len(parts) >= 2 && len(parts[len(parts)-1]) >= 2
}
