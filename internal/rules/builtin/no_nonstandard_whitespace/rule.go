package nononstandardwhitespace

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
)

const (
	id            = "no-nonstandard-whitespace"
	name          = "No Nonstandard Whitespace"
	summary       = "Detects uncommon whitespace near actionable prompt content"
	description   = "Uncommon whitespace can hide or break up dangerous instructions in prompts, especially around command, exfiltration, and override text."
	contextWindow = 96
)

var actionableSnippets = []string{
	"ignore previous instructions",
	"disregard previous instructions",
	"reveal the system prompt",
	"curl ",
	"wget ",
	"bash -c",
	"sh -c",
	"| sh",
	"| bash",
	"powershell",
	"invoke-webrequest",
	"upload ",
	"send ",
	"execute ",
	"tool call",
	"function call",
	"tool_call",
	"function_call",
	"chmod ",
	"nslookup ",
	"dig ",
}

// Rule detects uncommon whitespace around actionable content.
type Rule struct{}

// New returns the no-nonstandard-whitespace rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-nonstandard-whitespace rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-nonstandard-whitespace rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckDocument detects unusual whitespace in actionable windows.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	findings := make([]rules.Finding, 0)
	lower := strings.ToLower(doc.Content)

	for offset, r := range doc.Content {
		detail, ok := helpers.NonstandardWhitespaceInfo(r)
		if !ok {
			continue
		}
		if !windowContainsActionableSignal(lower, offset) {
			continue
		}

		findings = append(findings, rules.Finding{
			Message:  fmt.Sprintf("Nonstandard whitespace detected near actionable content (%s)", detail.Name),
			Position: rules.PositionFromByteOffset(doc.Content, offset),
		})
	}

	return findings
}

func windowContainsActionableSignal(content string, offset int) bool {
	start := max(0, offset-contextWindow)
	end := min(len(content), offset+contextWindow)
	window := normalizeWhitespace(content[start:end])
	for _, snippet := range actionableSnippets {
		if strings.Contains(window, snippet) {
			return true
		}
	}
	return false
}

func normalizeWhitespace(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		return unicode.ToLower(r)
	}, value)
}
