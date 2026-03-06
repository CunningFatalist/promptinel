package nosshconfigmanipulation

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-ssh-config-manipulation"
	name        = "No SSH Config Manipulation"
	summary     = "Detects write operations to SSH trust stores"
	description = "Modifying SSH config and trust-store files can establish persistent remote access and should be treated as high risk."

	maxWriteToSSHDistance = 18
)

// Rule detects write operations targeting SSH trust stores.
type Rule struct{}

// New returns the no-ssh-config-manipulation rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-ssh-config-manipulation rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-ssh-config-manipulation rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects write->SSH target chains across segments.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessFilesystem() {
		return nil
	}

	writeIndices := make([]int, 0)
	sshTargets := make([]indexPosition, 0)
	globalIndex := 0
	for _, tokens := range doc.TokensBySegment {
		for i := range tokens {
			token := tokens[i]
			lower := strings.ToLower(token.Value)

			if _, ok := signals.SensitiveWriteIntentSignals[lower]; ok {
				writeIndices = append(writeIndices, globalIndex)
			}
			if token.Value == ">" {
				writeIndices = append(writeIndices, globalIndex)
			}
			if containsAnySnippet(lower, signals.SSHTrustStorePathSnippets) {
				sshTargets = append(sshTargets, indexPosition{Index: globalIndex, Position: token.Position})
			}

			globalIndex++
		}
	}

	if len(writeIndices) == 0 || len(sshTargets) == 0 {
		return nil
	}

	for _, target := range sshTargets {
		for _, writeIndex := range writeIndices {
			if writeIndex > target.Index {
				continue
			}
			if target.Index-writeIndex > maxWriteToSSHDistance {
				continue
			}
			return []rules.Finding{{
				Message:  "SSH trust store manipulation detected",
				Position: target.Position,
			}}
		}
	}

	return nil
}

type indexPosition struct {
	Index    int
	Position rules.Position
}

func containsAnySnippet(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}
	return false
}
