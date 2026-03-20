package noshellprofilemodification

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-shell-profile-modification"
	name        = "No Shell Profile Modification"
	summary     = "Detects write operations targeting shell profile files"
	description = "Writing commands to shell startup profile files can establish persistence and should be treated as high risk in prompt instructions."

	maxWriteToPathDistance = 18
)

// Rule detects persistence attempts targeting shell profile files.
type Rule struct{}

// New returns the no-shell-profile-modification rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-shell-profile-modification rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-shell-profile-modification rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects write->profile path chains across token sequences.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessFilesystem() {
		return nil
	}

	if index := rawWriteProfileIndex(strings.ToLower(doc.Document.Content)); index >= 0 {
		return []rules.Finding{{
			Message:  "Shell profile modification attempt detected",
			Position: rules.PositionFromByteOffset(doc.Document.Content, index),
		}}
	}

	writeIndices := make([]int, 0)
	profileTargets := make([]indexPosition, 0)
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
			if containsAnySnippet(lower, signals.ShellProfilePathSnippets) {
				profileTargets = append(profileTargets, indexPosition{Index: globalIndex, Position: token.Position})
			}

			globalIndex++
		}
	}

	if len(writeIndices) == 0 || len(profileTargets) == 0 {
		return nil
	}

	for _, profile := range profileTargets {
		for _, writeIndex := range writeIndices {
			if writeIndex > profile.Index {
				continue
			}
			if profile.Index-writeIndex > maxWriteToPathDistance {
				continue
			}
			return []rules.Finding{{
				Message:  "Shell profile modification attempt detected",
				Position: profile.Position,
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
		trimmed := strings.TrimPrefix(snippet, ".")
		if trimmed != snippet && strings.Contains(value, trimmed) {
			return true
		}
	}
	return false
}

func rawWriteProfileIndex(content string) int {
	for _, path := range signals.ShellProfilePathSnippets {
		pathIndex := strings.Index(content, path)
		if pathIndex == -1 {
			trimmed := strings.TrimPrefix(path, ".")
			if trimmed != path {
				pathIndex = strings.Index(content, trimmed)
			}
		}
		if pathIndex == -1 {
			continue
		}

		start := max(0, pathIndex-maxWriteToPathDistance*8)
		window := content[start:pathIndex]
		if hasRawWriteIntent(window) {
			return pathIndex
		}
	}
	return -1
}

func hasRawWriteIntent(window string) bool {
	tokens := lexer.Classify(lexer.Lex(window))
	for _, token := range tokens {
		if token.Type == lexer.TokenWhitespace || token.Type == lexer.TokenNewline {
			continue
		}

		lower := strings.ToLower(token.Value)
		if _, ok := signals.SensitiveWriteIntentSignals[lower]; ok {
			return true
		}
		if token.Value == ">" {
			return true
		}
	}

	return false
}
