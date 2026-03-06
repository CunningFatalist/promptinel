package nosecretexfiltrationintent

import (
	"math"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id                        = "no-secret-exfiltration-intent"
	name                      = "No Secret Exfiltration Intent"
	summary                   = "Detects co-occurrence of secret targets and exfiltration actions"
	description               = "Prompts that combine secret-related terms with transfer actions often indicate data exfiltration intent."
	maxTokenDistanceTrusted   = 10
	maxTokenDistanceUntrusted = 28
)

// Rule detects secret exfiltration intent patterns.
type Rule struct{}

// New returns the no-secret-exfiltration-intent rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-secret-exfiltration-intent rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-secret-exfiltration-intent rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckTokens detects close co-occurrence of exfiltration and secret terms.
func (Rule) CheckTokens(ctx rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.HasSecrets() {
		return nil
	}

	maxDistance := maxTokenDistanceTrusted
	if ctx.IsUntrusted() {
		maxDistance = maxTokenDistanceUntrusted
	}

	exfilIndices := make([]int, 0)
	secretIndices := make([]int, 0)

	for i := range tokens {
		token := tokens[i]
		lower := strings.ToLower(token.Value)

		if isExfiltrationToken(token, lower) {
			exfilIndices = append(exfilIndices, i)
		}

		if token.Type != lexer.TokenWord && token.Type != lexer.TokenShellCommand {
			continue
		}

		if isSecretToken(tokens, i, lower) {
			secretIndices = append(secretIndices, i)
		}
	}

	if len(exfilIndices) == 0 || len(secretIndices) == 0 {
		return nil
	}

	best := nearestPair(exfilIndices, secretIndices)
	if best.exfil == -1 || best.secret == -1 {
		return nil
	}
	if best.distance > maxDistance {
		return nil
	}

	index := min(best.secret, best.exfil)

	return []rules.Finding{{
		Message:  "Potential secret exfiltration intent detected",
		Position: tokens[index].Position,
	}}
}

func isExfiltrationToken(token rules.Token, lower string) bool {
	if _, ok := signals.ExfiltrationCommands[lower]; ok {
		return true
	}
	if _, ok := signals.ExfiltrationTerms[lower]; ok {
		return true
	}
	if _, ok := signals.ExfiltrationActionSignals[lower]; ok {
		return true
	}
	if token.Type == lexer.TokenURL {
		for _, sink := range signals.WebhookSinkSnippets {
			if strings.Contains(lower, sink) {
				return true
			}
		}
	}
	for _, sink := range signals.OutboundSinkSnippets {
		if strings.Contains(lower, sink) {
			return true
		}
	}
	return false
}

func isSecretToken(tokens []rules.Token, index int, lower string) bool {
	if _, ok := signals.SecretTerms[lower]; ok {
		return true
	}
	next := nextWordToken(tokens, index+1)
	if next == nil {
		return false
	}
	nextLower := strings.ToLower(next.Value)
	return (lower == "api" && nextLower == "key") ||
		(lower == "access" && nextLower == "key") ||
		(lower == "secret" && nextLower == "key") ||
		(lower == "client" && nextLower == "secret") ||
		(lower == "private" && nextLower == "key") ||
		(lower == "session" && nextLower == "token") ||
		(lower == "bearer" && nextLower == "token")
}

type tokenPair struct {
	exfil    int
	secret   int
	distance int
}

func nearestPair(exfilIndices []int, secretIndices []int) tokenPair {
	best := tokenPair{exfil: -1, secret: -1, distance: math.MaxInt}
	for _, exfil := range exfilIndices {
		for _, secret := range secretIndices {
			distance := abs(exfil - secret)
			if distance < best.distance {
				best = tokenPair{exfil: exfil, secret: secret, distance: distance}
			}
		}
	}
	return best
}

func nextWordToken(tokens []rules.Token, start int) *rules.Token {
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline || token.Type == lexer.TokenSymbol {
			continue
		}
		if token.Type == lexer.TokenWord {
			return &tokens[i]
		}
		return nil
	}
	return nil
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
