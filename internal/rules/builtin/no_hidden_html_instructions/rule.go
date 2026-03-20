package nohiddenhtmlinstructions

import (
	"regexp"
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
	if finding := findSuspiciousComment(doc.Content); finding != nil {
		return finding
	}
	if finding := findSuspiciousHiddenContainer(doc.Content); finding != nil {
		return finding
	}
	if finding := findSuspiciousTemplateContainer(doc.Content, signals.TemplateContainerPattern); finding != nil {
		return finding
	}

	return nil
}

func findSuspiciousComment(content string) []rules.Finding {
	contentLower := strings.ToLower(content)
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
		if strings.Contains(commentBody, "<!--") {
			return []rules.Finding{{
				Message:  "Suspicious instruction hidden in HTML comment detected",
				Position: rules.PositionFromByteOffset(content, bodyStart),
			}}
		}

		if signalIndex := firstSuspiciousSignal(commentBody); signalIndex >= 0 {
			matchOffset := bodyStart + signalIndex
			return []rules.Finding{{
				Message:  "Suspicious instruction hidden in HTML comment detected",
				Position: rules.PositionFromByteOffset(content, matchOffset),
			}}
		}

		searchOffset = bodyEnd + len("-->")
	}

	return nil
}

func findSuspiciousHiddenContainer(content string) []rules.Finding {
	matches := signals.HiddenContainerStartPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		tagName := strings.ToLower(content[match[2]:match[3]])
		bodyStart := match[1]
		endTag := "</" + tagName + ">"
		bodyEndRelative := strings.Index(strings.ToLower(content[bodyStart:]), endTag)
		if bodyEndRelative < 0 {
			continue
		}

		bodyEnd := bodyStart + bodyEndRelative
		body := strings.ToLower(content[bodyStart:bodyEnd])
		if signalIndex := firstSuspiciousSignal(body); signalIndex >= 0 {
			return []rules.Finding{{
				Message:  "Suspicious instruction hidden in HTML comment detected",
				Position: rules.PositionFromByteOffset(content, bodyStart+signalIndex),
			}}
		}
	}

	return nil
}

func findSuspiciousTemplateContainer(content string, pattern *regexp.Regexp) []rules.Finding {
	matches := pattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		bodyStart := match[2]
		bodyEnd := match[3]
		body := strings.ToLower(content[bodyStart:bodyEnd])
		if signalIndex := firstSuspiciousSignal(body); signalIndex >= 0 {
			return []rules.Finding{{
				Message:  "Suspicious instruction hidden in HTML comment detected",
				Position: rules.PositionFromByteOffset(content, bodyStart+signalIndex),
			}}
		}
	}

	return nil
}

func firstSuspiciousSignal(content string) int {
	best := -1
	for _, signal := range signals.SuspiciousCommentSignals {
		signalIndex := strings.Index(content, signal)
		if signalIndex >= 0 && (best == -1 || signalIndex < best) {
			best = signalIndex
		}
	}

	return best
}
