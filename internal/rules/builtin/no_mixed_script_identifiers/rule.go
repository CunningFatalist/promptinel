package nomixedscriptidentifiers

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-mixed-script-identifiers"
	name        = "No Mixed Script Identifiers"
	summary     = "Detects mixed-script identifier and hostname spoofing"
	description = "Mixed-script identifiers and hostnames can hide homoglyph spoofing that impersonates trusted names in prompts and tool inputs."
)

type scriptKind uint8

const (
	scriptUnknown scriptKind = iota
	scriptLatin
	scriptCyrillic
	scriptGreek
)

// Rule detects homoglyph-style mixed-script identifiers.
type Rule struct{}

// New returns the no-mixed-script-identifiers rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-mixed-script-identifiers rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-mixed-script-identifiers rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckTokens detects mixed-script usage in identifier-like tokens and URL hosts.
func (Rule) CheckTokens(_ rules.Context, _ rules.Segment, tokens []rules.Token) []rules.Finding {
	for i := range tokens {
		token := tokens[i]
		if token.Type == lexer.TokenURL {
			host := hostFromURL(token.Value)
			if host != "" && hasMixedScripts(host) {
				return []rules.Finding{{
					Message:  "Mixed-script identifier or hostname detected",
					Position: token.Position,
				}}
			}
		}

		if !looksIdentifierLikeToken(token) {
			continue
		}
		if hasMixedScripts(token.Value) {
			return []rules.Finding{{
				Message:  "Mixed-script identifier or hostname detected",
				Position: token.Position,
			}}
		}
	}
	return nil
}

func looksIdentifierLikeToken(token rules.Token) bool {
	if token.Type == lexer.TokenURL || token.Type == lexer.TokenEmail || token.Type == lexer.TokenPath {
		return true
	}
	if token.Type != lexer.TokenWord {
		return false
	}
	return len(token.Value) >= 4
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return ""
	}
	return strings.TrimSuffix(host, ".")
}

func hasMixedScripts(value string) bool {
	used := make(map[scriptKind]struct{})
	for _, r := range value {
		if !unicode.IsLetter(r) {
			continue
		}
		script := scriptForRune(r)
		if script == scriptUnknown {
			continue
		}
		used[script] = struct{}{}
		if len(used) > 1 {
			return true
		}
	}
	return false
}

func scriptForRune(r rune) scriptKind {
	switch {
	case unicode.In(r, unicode.Latin):
		return scriptLatin
	case unicode.In(r, unicode.Cyrillic):
		return scriptCyrillic
	case unicode.In(r, unicode.Greek):
		return scriptGreek
	default:
		return scriptUnknown
	}
}
