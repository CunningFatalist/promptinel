package nometadataserviceaccess

import (
	"net"
	"net/url"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-metadata-service-access"
	name        = "No Metadata Service Access"
	summary     = "Detects URLs targeting cloud instance metadata endpoints"
	description = "Cloud metadata services can expose credentials and environment secrets when accessed from compromised prompts."
)

var metadataHosts = map[string]struct{}{
	"169.254.169.254":          {},
	"169.254.170.2":            {},
	"100.100.100.200":          {},
	"metadata.google.internal": {},
}

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
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	findings := make([]rules.Finding, 0)
	for _, token := range tokens {
		if token.Type != lexer.TokenURL {
			continue
		}

		host := hostFromURL(token.Value)
		if host == "" {
			continue
		}
		if _, ok := metadataHosts[host]; !ok {
			continue
		}

		findings = append(findings, rules.Finding{
			Message:  "Cloud metadata service URL detected",
			Position: token.Position,
		})
	}
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
	return host
}
