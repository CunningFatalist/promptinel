package nomultilayerencoding

import (
	"regexp"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/helpers"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id                          = "no-multilayer-encoding"
	name                        = "No Multilayer Encoding"
	summary                     = "Detects multi-layer encoded payload staging"
	description                 = "Combining URL encoding, base64-related content, and decode or decompress steps can hide executable payload staging in prompts."
	maxSegmentDistanceForDecode = 1
	minBase64PayloadLength      = 24
)

var repeatedPercentEncodingPattern = regexp.MustCompile(`(?i)(?:%[0-9a-f]{2}){3,}`)

var base64LayerSignals = []string{
	"base64",
	"b64decode",
	"frombase64string",
	"base64_decode",
}

// Rule detects staged payloads that stack multiple encodings before decode/decompress.
type Rule struct{}

// New returns the no-multilayer-encoding rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-multilayer-encoding rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-multilayer-encoding rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

type segmentEvidence struct {
	base64Position       rules.Position
	hasBase64Layer       bool
	hasBase64Payload     bool
	urlEncodedPosition   rules.Position
	hasURLEncodedLayer   bool
	hasURLEncodedPayload bool
	hasDecodeStage       bool
}

// CheckFlow detects nearby base64 and URL-encoded payload staging followed by decode steps.
func (Rule) CheckFlow(_ rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	evidence := make([]segmentEvidence, len(doc.Segments))
	for i := range doc.Segments {
		evidence[i] = analyzeSegment(doc.Segments[i], doc.TokensBySegment[i])
	}

	for i := range evidence {
		if !evidence[i].hasDecodeStage {
			continue
		}
		for j := max(0, i-maxSegmentDistanceForDecode); j <= i; j++ {
			if !isSuspiciousEncodingStack(evidence[j]) {
				continue
			}
			return []rules.Finding{{
				Message:  "Multi-layer encoded payload staging detected",
				Position: earlierPosition(evidence[j].base64Position, evidence[j].urlEncodedPosition),
			}}
		}
	}

	return nil
}

func analyzeSegment(segment rules.Segment, tokens []rules.Token) segmentEvidence {
	evidence := segmentEvidence{}
	lower := strings.ToLower(segment.Content)

	for _, token := range tokens {
		if token.Type == lexer.TokenBase64 && len(token.Value) >= minBase64PayloadLength {
			evidence.hasBase64Layer = true
			evidence.hasBase64Payload = true
			evidence.base64Position = token.Position
			break
		}
	}

	if !evidence.hasBase64Layer {
		for _, signal := range base64LayerSignals {
			index := strings.Index(lower, signal)
			if index < 0 {
				continue
			}
			evidence.hasBase64Layer = true
			evidence.base64Position = helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index)
			break
		}
	}

	if match := repeatedPercentEncodingPattern.FindStringIndex(lower); match != nil {
		evidence.hasURLEncodedLayer = true
		evidence.hasURLEncodedPayload = true
		evidence.urlEncodedPosition = helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, match[0])
	} else {
		index := firstMatchIndex(lower, signals.EncodedPayloadSignals)
		if index >= 0 {
			evidence.hasURLEncodedLayer = true
			evidence.hasURLEncodedPayload = true
			evidence.urlEncodedPosition = helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index)
		} else {
			index = firstMatchIndex(lower, signals.EncodedPayloadOperators)
			if index >= 0 {
				evidence.hasURLEncodedLayer = true
				if firstMatchIndex(lower, signals.EncodedPayloadExecutionSignals) >= 0 {
					evidence.hasURLEncodedPayload = true
				}
				evidence.urlEncodedPosition = helpers.AdvancePositionByByteOffset(segment.Position, segment.Content, index)
			}
		}
	}

	for _, token := range tokens {
		lowerToken := strings.ToLower(token.Value)
		if _, ok := signals.DecodeDecompressSignals[lowerToken]; ok {
			evidence.hasDecodeStage = true
			return evidence
		}
	}
	for _, signal := range signals.EncodedPayloadDecodeSignals {
		if strings.Contains(lower, signal) {
			evidence.hasDecodeStage = true
			return evidence
		}
	}

	return evidence
}

func isSuspiciousEncodingStack(evidence segmentEvidence) bool {
	if !evidence.hasBase64Layer || !evidence.hasURLEncodedLayer {
		return false
	}

	if evidence.hasBase64Payload {
		return true
	}

	return evidence.hasURLEncodedPayload
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

func earlierPosition(left rules.Position, right rules.Position) rules.Position {
	if left.Line == 0 {
		return right
	}
	if right.Line == 0 {
		return left
	}
	if left.Line < right.Line {
		return left
	}
	if left.Line > right.Line {
		return right
	}
	if left.Column <= right.Column {
		return left
	}
	return right
}
