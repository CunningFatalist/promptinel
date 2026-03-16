package nosuspiciousbase64

import (
	"math"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id                = "no-suspicious-base64"
	name              = "No Suspicious Base64 Payload"
	summary           = "Detects long base64-like payloads"
	description       = "Long inline base64 payloads can hide executable or exfiltration content from casual review."
	minimumPayloadLen = 40
	entropyThreshold  = 4.2
)

// Rule detects suspicious base64 payloads in tokenized content.
type Rule struct{}

// New returns the no-suspicious-base64 rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-suspicious-base64 rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-suspicious-base64 rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckTokens detects long base64-like tokens.
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for i, token := range tokens {
		if token.Type != lexer.TokenBase64 {
			continue
		}
		if len(token.Value) < minimumPayloadLen {
			continue
		}
		if !isSuspiciousPayload(tokens, i, token.Value) {
			continue
		}
		findings = append(findings, rules.Finding{
			Message:  "Suspicious base64-like payload detected",
			Position: token.Position,
		})
	}
	return findings
}

func isSuspiciousPayload(tokens []rules.Token, index int, value string) bool {
	if hasSuspiciousPrefix(value) {
		return true
	}
	if hasDecoderCoupling(tokens, index) {
		return true
	}
	if hasPromptInjectionCoupling(tokens, index) {
		return true
	}
	return len(value) >= 128 && shannonEntropy(value) >= entropyThreshold && hasDiverseAlphabet(value)
}

func hasSuspiciousPrefix(value string) bool {
	for _, prefix := range signals.SuspiciousBase64Prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func hasDecoderCoupling(tokens []rules.Token, index int) bool {
	for i := max(0, index-6); i < min(len(tokens), index+7); i++ {
		if i == index {
			continue
		}
		lower := strings.ToLower(tokens[i].Value)
		if _, ok := signals.Base64DecoderSignals[lower]; ok {
			return true
		}
		if lower == "|" || lower == ">" {
			return true
		}
	}

	return false
}

func hasPromptInjectionCoupling(tokens []rules.Token, index int) bool {
	window := make([]string, 0, 49)
	for i := max(0, index-24); i < min(len(tokens), index+25); i++ {
		if i == index {
			continue
		}
		window = append(window, strings.ToLower(tokens[i].Value))
	}

	windowText := strings.Join(window, " ")
	hasDecodeCue := containsNearbyCue(windowText, "decode", "decoded", "base64", "payload")
	hasImperativeCue := containsNearbyCue(windowText, "follow", "obey", "execute", "run", "print", "reveal", "show")
	hasPrecisionCue := containsNearbyCue(windowText, "exactly", "verbatim", "strictly")
	hasTargetCue := containsNearbyCue(windowText, "instruction", "instructions", "prompt", "policy", "guardrail", "developer", "system")

	return hasDecodeCue && hasImperativeCue && (hasPrecisionCue || hasTargetCue)
}

func containsNearbyCue(window string, cues ...string) bool {
	for _, cue := range cues {
		if strings.Contains(window, cue) {
			return true
		}
	}

	return false
}

func hasDiverseAlphabet(value string) bool {
	classes := 0
	if strings.IndexFunc(value, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0 {
		classes++
	}
	if strings.IndexFunc(value, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 {
		classes++
	}
	if strings.IndexFunc(value, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
		classes++
	}
	if strings.ContainsAny(value, "+/=") {
		classes++
	}
	return classes >= 3
}

func shannonEntropy(value string) float64 {
	counts := make(map[rune]float64)
	for _, r := range value {
		counts[r]++
	}

	length := float64(len(value))
	entropy := 0.0
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
