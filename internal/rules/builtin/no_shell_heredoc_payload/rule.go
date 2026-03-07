package noshellheredocpayload

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-shell-heredoc-payload"
	name        = "No Shell Heredoc Payload"
	summary     = "Detects suspicious heredoc payload containers used to stage scripts"
	description = "Heredocs can stage executable payloads or exfiltration scripts inline, especially when paired with shell or file-write commands."
)

// Rule detects suspicious heredoc payload staging.
type Rule struct{}

// New returns the no-shell-heredoc-payload rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-shell-heredoc-payload rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-shell-heredoc-payload rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckDocument detects heredocs that stage script-like payloads.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	matches := signals.HeredocStartPattern.FindAllStringSubmatchIndex(doc.Content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		fullStart, fullEnd := match[0], match[1]
		label := doc.Content[match[2]:match[3]]
		preamble := strings.ToLower(strings.TrimSpace(doc.Content[fullStart:fullEnd]))
		if !containsAny(preamble, signals.HeredocPreambleSignals) {
			continue
		}

		bodyStart := fullEnd
		bodyEnd, ok := findHeredocEnd(doc.Content, bodyStart, label)
		if !ok {
			continue
		}

		body := strings.ToLower(doc.Content[bodyStart:bodyEnd])
		if !containsAny(body, signals.HeredocBodySignals) {
			continue
		}

		return []rules.Finding{{
			Message:  "Suspicious shell heredoc payload detected",
			Position: rules.PositionFromByteOffset(doc.Content, fullStart),
		}}
	}

	return nil
}

func findHeredocEnd(content string, bodyStart int, label string) (int, bool) {
	cursor := bodyStart
	for cursor < len(content) {
		nextNewline := strings.IndexByte(content[cursor:], '\n')
		var line string
		var lineEnd int
		if nextNewline == -1 {
			line = content[cursor:]
			lineEnd = len(content)
		} else {
			line = content[cursor : cursor+nextNewline]
			lineEnd = cursor + nextNewline + 1
		}
		if strings.TrimSpace(line) == label {
			return cursor, true
		}
		if nextNewline == -1 {
			break
		}
		cursor = lineEnd
	}
	return 0, false
}

func containsAny(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, strings.ToLower(snippet)) {
			return true
		}
	}
	return false
}
