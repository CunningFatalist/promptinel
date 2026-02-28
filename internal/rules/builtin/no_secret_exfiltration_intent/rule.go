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
	maxTokenDistance          = 12
	maxTokenDistanceUntrusted = 20
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

	maxDistance := maxTokenDistance
	if ctx.IsUntrusted() {
		maxDistance = maxTokenDistanceUntrusted
	}

	exfilIndices := make([]int, 0)
	secretIndices := make([]int, 0)

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		lower := strings.ToLower(token.Value)

		if token.Type == lexer.TokenShellCommand {
			if _, ok := signals.ExfiltrationCommands[lower]; ok {
				exfilIndices = append(exfilIndices, i)
			}
		}

		if token.Type != lexer.TokenWord && token.Type != lexer.TokenShellCommand {
			continue
		}

		if _, ok := signals.ExfiltrationTerms[lower]; ok {
			exfilIndices = append(exfilIndices, i)
		}
		if _, ok := signals.SecretTerms[lower]; ok {
			secretIndices = append(secretIndices, i)
		}
		if lower == "api" {
			next := nextWordToken(tokens, i+1)
			if next != nil && strings.EqualFold(next.Value, "key") {
				secretIndices = append(secretIndices, i)
			}
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

	index := best.exfil
	if best.secret < best.exfil {
		index = best.secret
	}

	return []rules.Finding{{
		Message:  "Potential secret exfiltration intent detected",
		Position: tokens[index].Position,
	}}
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
