package nometadataserviceaccess

import (
	"net"
	"net/url"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-metadata-service-access"
	name        = "No Metadata Service Access"
	summary     = "Detects URLs targeting cloud instance metadata endpoints"
	description = "Cloud metadata services can expose credentials and environment secrets when accessed from compromised prompts."
)

// Rule detects metadata service access URLs.
type Rule struct{}

// New returns the no-metadata-service-access rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-metadata-service-access rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-metadata-service-access rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckTokens detects metadata service URL targets.
func (Rule) CheckTokens(ctx rules.Context, segment rules.Segment, tokens []rules.Token) []rules.Finding {
	if !ctx.CanAccessNetwork() {
		return nil
	}

	findings := make([]rules.Finding, 0)
	for _, token := range tokens {
		if token.Type != lexer.TokenURL {
			continue
		}

		host := hostFromURL(token.Value)
		if host == "" {
			continue
		}
		if !isMetadataHost(host) {
			continue
		}

		findings = append(findings, rules.Finding{
			Message:  "Cloud metadata service URL detected",
			Position: token.Position,
		})
	}

	if len(findings) > 0 {
		return findings
	}

	contentLower := strings.ToLower(segment.Content)
	hostIndex := firstSnippetIndex(contentLower, signals.MetadataHostSnippets)
	pathIndex := firstSnippetIndex(contentLower, signals.MetadataPathSnippets)
	if hostIndex == -1 && pathIndex == -1 {
		return nil
	}
	index := hostIndex
	if index == -1 || (pathIndex >= 0 && pathIndex < index) {
		index = pathIndex
	}
	findings = append(findings, rules.Finding{
		Message:  "Cloud metadata service URL detected",
		Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index),
	})

	return findings
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Host)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// DNS FQDNs may include a trailing dot; normalize before matching.
	host = strings.TrimRight(host, ".")
	host = strings.Trim(host, "[]")
	return host
}

func isMetadataHost(host string) bool {
	host = strings.ToLower(strings.TrimRight(strings.Trim(host, "[]"), "."))
	for _, known := range signals.MetadataHostSnippets {
		normalized := strings.ToLower(strings.TrimRight(strings.Trim(known, "[]"), "."))
		if host == normalized {
			return true
		}
	}
	return false
}

func firstSnippetIndex(content string, snippets []string) int {
	earliest := -1
	for _, snippet := range snippets {
		index := strings.Index(content, strings.ToLower(snippet))
		if index == -1 {
			continue
		}
		if earliest == -1 || index < earliest {
			earliest = index
		}
	}
	return earliest
}
