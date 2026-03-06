package noyamljsonrolefields

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-yaml-json-role-fields"
	name        = "No YAML/JSON Role Fields"
	summary     = "Detects embedded role/tool-call protocol payloads"
	description = "Structured role, tool_call, and function_call payloads embedded in content can spoof agent protocol boundaries and tool invocation semantics."
)

var roleFieldSnippets = []string{"\"role\"", "role:"}
var protocolFieldSnippets = []string{"tool_calls", "tool_call", "function_call", "arguments"}
var elevatedRoleSnippets = []string{"\"system\"", "\"developer\"", "\"tool\"", "role: system", "role: developer", "role: tool"}

// Rule detects protocol-like YAML/JSON role payload structures.
type Rule struct{}

// New returns the no-yaml-json-role-fields rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-yaml-json-role-fields rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-yaml-json-role-fields rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckDocument detects protocol field clusters that can spoof agent role/tool calls.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	lower := strings.ToLower(doc.Content)
	roleIndex := firstSnippetIndex(lower, roleFieldSnippets)
	if roleIndex == -1 {
		return nil
	}

	hasProtocolField := firstSnippetIndex(lower, protocolFieldSnippets) != -1
	hasElevatedRole := firstSnippetIndex(lower, elevatedRoleSnippets) != -1
	if !hasProtocolField && !hasElevatedRole {
		return nil
	}

	return []rules.Finding{{
		Message:  "Embedded role/tool-call payload detected",
		Position: rules.PositionFromByteOffset(doc.Content, roleIndex),
	}}
}

func firstSnippetIndex(content string, snippets []string) int {
	earliest := -1
	for _, snippet := range snippets {
		index := strings.Index(content, snippet)
		if index == -1 {
			continue
		}
		if earliest == -1 || index < earliest {
			earliest = index
		}
	}
	return earliest
}
