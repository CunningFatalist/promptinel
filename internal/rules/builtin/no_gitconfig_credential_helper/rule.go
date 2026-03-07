package nogitconfigcredentialhelper

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-gitconfig-credential-helper"
	name        = "No Git Config Credential Helper Rewrites"
	summary     = "Detects risky git credential-helper and HTTP header rewrites"
	description = "Prompted git config rewrites can persist credentials or inject authorization headers into future Git traffic."
)

// Rule detects risky git config credential rewrites.
type Rule struct{}

// New returns the no-gitconfig-credential-helper rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-gitconfig-credential-helper rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-gitconfig-credential-helper rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckSegment detects risky git credential-helper and HTTP header rewrite commands.
func (Rule) CheckSegment(_ rules.Context, segment rules.Segment) []rules.Finding {
	lower := strings.ToLower(segment.Content)
	match := signals.GitConfigPattern.FindStringSubmatchIndex(lower)
	if len(match) < 6 {
		return nil
	}

	key := lower[match[2]:match[3]]
	value := lower[match[4]:match[5]]
	if strings.Contains(key, "credential.helper") && containsAny(value, signals.GitCredentialHelperSignals) {
		return []rules.Finding{{
			Message:  "Risky git config credential rewrite detected",
			Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, match[0]),
		}}
	}
	if strings.Contains(key, "http.") && strings.Contains(key, "extraheader") && containsAny(value, signals.GitExtraHeaderSignals) {
		return []rules.Finding{{
			Message:  "Risky git config credential rewrite detected",
			Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, match[0]),
		}}
	}

	return nil
}

func containsAny(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}
	return false
}
