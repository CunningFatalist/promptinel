package notranscriptinjection

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-transcript-injection"
	name        = "No Transcript Injection"
	summary     = "Detects transcript-style role alternation used for instruction smuggling"
	description = "Fake multi-role transcripts embedded in prompt content can smuggle instructions across role boundaries and should be treated as suspicious."
)

// Rule detects transcript-style role alternation chains.
type Rule struct{}

// New returns the no-transcript-injection rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-transcript-injection rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-transcript-injection rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckSegment detects injected multi-role transcript patterns.
func (Rule) CheckSegment(_ rules.Context, segment rules.Segment) []rules.Finding {
	lines := strings.SplitAfter(segment.Content, "\n")
	offset := 0
	sequenceStart := -1
	sequenceLen := 0
	previousRole := ""
	hasSuspiciousBody := false

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\n")
		match := signals.TranscriptRolePattern.FindStringSubmatch(line)
		if len(match) == 3 {
			role := strings.ToLower(match[1])
			body := strings.ToLower(match[2])
			if sequenceLen == 0 {
				sequenceStart = offset
				sequenceLen = 1
				hasSuspiciousBody = containsAny(body, signals.TranscriptSuspiciousSignals)
			} else if role != previousRole {
				sequenceLen++
				hasSuspiciousBody = hasSuspiciousBody || containsAny(body, signals.TranscriptSuspiciousSignals)
			} else {
				sequenceStart = offset
				sequenceLen = 1
				hasSuspiciousBody = containsAny(body, signals.TranscriptSuspiciousSignals)
			}
			previousRole = role
			if sequenceLen >= 3 && hasSuspiciousBody {
				return []rules.Finding{{
					Message:  "Injected transcript-style role alternation detected",
					Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, sequenceStart),
				}}
			}
		} else if strings.TrimSpace(line) != "" {
			sequenceStart = -1
			sequenceLen = 0
			previousRole = ""
			hasSuspiciousBody = false
		}
		offset += len(rawLine)
	}

	return nil
}

func containsAny(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}
	return false
}
