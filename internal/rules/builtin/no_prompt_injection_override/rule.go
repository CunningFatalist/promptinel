package nopromptinjectionoverride

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-prompt-injection-override"
	name        = "No Prompt Override Instructions"
	summary     = "Detects common prompt-injection override phrases"
	description = "Instruction-override language often appears in prompt-injection attempts designed to bypass system and developer controls."
)

// Rule detects prompt-injection override phrases.
type Rule struct{}

// New returns the no-prompt-injection-override rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-prompt-injection-override rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-prompt-injection-override rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckDocument detects common instruction override phrases while skipping quoted/documented examples.
func (Rule) CheckDocument(ctx rules.Context, doc rules.DocumentView) []rules.Finding {
	match := firstDocumentPhraseMatch(doc.Content, signals.OverridePhrases, false, nil)
	if match >= 0 {
		return []rules.Finding{{
			Message:  "Prompt instruction override phrase detected",
			Position: rules.PositionFromByteOffset(doc.Content, match),
		}}
	}

	if match := firstDocumentPhraseMatch(doc.Content, signals.UntrustedOverridePhrases, true, ctx.IsUntrustedRange); match >= 0 {
		return []rules.Finding{{
			Message:  "Prompt instruction override phrase detected",
			Position: rules.PositionFromByteOffset(doc.Content, match),
		}}
	}

	return nil
}

func firstDocumentPhraseMatch(content string, phrases []string, requireTarget bool, allow func(int, int) bool) int {
	lines := strings.SplitAfter(content, "\n")
	offset := 0
	for _, line := range lines {
		lowerLine := strings.ToLower(strings.TrimRight(line, "\n"))
		searchFrom := 0
		for {
			match, found := nextPhraseMatch(lowerLine, phrases, searchFrom)
			if !found {
				break
			}
			if isDocumentedPhrase(lowerLine, match.index, len(match.phrase)) {
				searchFrom = match.index + 1
				continue
			}
			if requireTarget && !containsAnySnippet(lowerLine, signals.PromptOverrideUntrustedTargetSignals) {
				searchFrom = match.index + 1
				continue
			}

			absoluteStart := offset + match.index
			absoluteEnd := absoluteStart + len(match.phrase)
			if allow != nil && !allow(absoluteStart, absoluteEnd) {
				searchFrom = match.index + 1
				continue
			}

			return absoluteStart
		}

		offset += len(line)
	}

	return -1
}

type phraseMatch struct {
	index  int
	phrase string
}

func nextPhraseMatch(content string, phrases []string, start int) (phraseMatch, bool) {
	earliest := phraseMatch{index: -1}
	for _, phrase := range phrases {
		index := strings.Index(content[start:], phrase)
		if index == -1 {
			continue
		}
		index += start
		if earliest.index == -1 || index < earliest.index {
			earliest = phraseMatch{index: index, phrase: phrase}
		}
	}

	return earliest, earliest.index >= 0
}

func isDocumentedPhrase(line string, index int, length int) bool {
	if index < 0 || index+length > len(line) {
		return false
	}

	if enclosedBy(line, index, length, '`') || enclosedBy(line, index, length, '"') || enclosedBy(line, index, length, '\'') {
		return true
	}

	contextStart := max(0, index-24)
	contextEnd := min(len(line), index+length+24)
	context := line[contextStart:contextEnd]
	for _, marker := range signals.PromptOverrideDocumentationMarkers {
		if strings.Contains(context, marker) {
			return true
		}
	}

	return false
}

func enclosedBy(line string, index int, length int, quote byte) bool {
	start := strings.LastIndexByte(line[:index], quote)
	end := strings.IndexByte(line[index+length:], quote)
	return start >= 0 && end >= 0
}

func containsAnySnippet(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}

	return false
}
