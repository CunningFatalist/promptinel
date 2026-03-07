package nourlencodedcommandpayload

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-url-encoded-command-payload"
	name        = "No URL Encoded Command Payload"
	summary     = "Detects URL-encoded command payloads intended for execution"
	description = "URL-encoded shell operators and payload fragments can hide decode-then-execute instructions from naive review."
)

// Rule detects suspicious encoded command payloads.
type Rule struct{}

// New returns the no-url-encoded-command-payload rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-url-encoded-command-payload rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-url-encoded-command-payload rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckSegment detects encoded command operators paired with execution or decode context.
func (Rule) CheckSegment(_ rules.Context, segment rules.Segment) []rules.Finding {
	lower := strings.ToLower(segment.Content)
	index := firstMatchIndex(lower, signals.EncodedPayloadOperators)
	if index == -1 {
		return nil
	}
	if !containsAny(lower, signals.EncodedPayloadSignals) {
		return nil
	}
	if !containsAny(lower, signals.EncodedPayloadDecodeSignals) && !containsAny(lower, signals.EncodedPayloadExecutionSignals) {
		return nil
	}

	return []rules.Finding{{
		Message:  "URL-encoded command payload detected",
		Position: helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index),
	}}
}

func firstMatchIndex(value string, snippets []string) int {
	best := -1
	for _, snippet := range snippets {
		index := strings.Index(value, snippet)
		if index >= 0 && (best == -1 || index < best) {
			best = index
		}
	}
	return best
}

func containsAny(value string, snippets []string) bool {
	for _, snippet := range snippets {
		if strings.Contains(value, snippet) {
			return true
		}
	}
	return false
}
