package nohiddenhtmlinstructions

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-hidden-html-instructions"
	name        = "No Hidden HTML Instructions"
	summary     = "Detects suspicious instructions inside HTML comments"
	description = "Hidden HTML comments can conceal instruction overrides and execution guidance in otherwise benign-looking prompt files."
)

// Rule detects suspicious hidden instructions in HTML comments.
type Rule struct{}

// New returns the no-hidden-html-instructions rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-hidden-html-instructions rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-hidden-html-instructions rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckDocument detects suspicious content hidden in HTML comments.
func (Rule) CheckDocument(_ rules.Context, doc rules.DocumentView) []rules.Finding {
	contentLower := strings.ToLower(doc.Content)
	searchOffset := 0

	for searchOffset < len(contentLower) {
		startRelative := strings.Index(contentLower[searchOffset:], "<!--")
		if startRelative < 0 {
			break
		}
		start := searchOffset + startRelative

		bodyStart := start + len("<!--")
		endRelative := strings.Index(contentLower[bodyStart:], "-->")
		if endRelative < 0 {
			break
		}

		bodyEnd := bodyStart + endRelative
		commentBody := contentLower[bodyStart:bodyEnd]
		for _, signal := range signals.SuspiciousCommentSignals {
			signalIndex := strings.Index(commentBody, signal)
			if signalIndex == -1 {
				continue
			}

			matchOffset := bodyStart + signalIndex
			return []rules.Finding{{
				Message:  "Suspicious instruction hidden in HTML comment detected",
				Position: rules.PositionFromByteOffset(doc.Content, matchOffset),
			}}
		}

		searchOffset = bodyEnd + len("-->")
	}

	return nil
}
