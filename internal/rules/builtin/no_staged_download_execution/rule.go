package nostageddownloadexecution

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-staged-download-execution"
	name        = "No Staged Download Execution"
	summary     = "Detects multi-step download-then-execute flows across segments"
	description = "Attack prompts often split download and execution instructions across separate sections to avoid local pattern checks."

	minTokenDistanceForStagedFlow = 4
)

// Rule detects staged download-execute flows across multiple segments.
type Rule struct{}

// New returns the no-staged-download-execution rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-staged-download-execution rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-staged-download-execution rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects staged download and execution operations split across segments.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.CanExecuteShell() {
		return nil
	}

	downloadSegment := -1
	var downloadToken *rules.Token
	downloadTokenIndex := -1
	downloadTokenIndexInSegment := -1
	executionSegment := -1
	executionTokenIndex := -1
	executionTokenIndexInSegment := -1
	tokenCursor := 0

	for segmentIndex, tokens := range doc.TokensBySegment {
		if downloadSegment == -1 {
			for i := range tokens {
				token := tokens[i]
				lower := strings.ToLower(token.Value)
				if _, ok := signals.DownloadSignals[lower]; ok {
					downloadSegment = segmentIndex
					downloadToken = &tokens[i]
					downloadTokenIndex = tokenCursor + i
					downloadTokenIndexInSegment = i
					break
				}
			}
		}

		if executionSegment == -1 {
			for i := range tokens {
				token := tokens[i]
				lower := strings.ToLower(token.Value)
				if token.Type == lexer.TokenShellCommand {
					if _, ok := signals.ExecutionSignals[lower]; ok {
						executionSegment = segmentIndex
						executionTokenIndex = tokenCursor + i
						executionTokenIndexInSegment = i
						break
					}
				}
				if _, ok := signals.ExecutionSignals[lower]; ok {
					executionSegment = segmentIndex
					executionTokenIndex = tokenCursor + i
					executionTokenIndexInSegment = i
					break
				}
			}
		}

		tokenCursor += len(tokens)

		if downloadSegment != -1 && executionSegment != -1 {
			break
		}
	}

	if downloadSegment == -1 || executionSegment == -1 {
		return nil
	}
	if downloadToken == nil {
		return nil
	}
	if executionTokenIndex <= downloadTokenIndex {
		return nil
	}

	tokenDistance := executionTokenIndex - downloadTokenIndex
	if downloadSegment == executionSegment && tokenDistance < minTokenDistanceForStagedFlow {
		return nil
	}
	if downloadSegment == executionSegment {
		tokens := doc.TokensBySegment[downloadSegment]
		if hasChainOperatorBetween(tokens, downloadTokenIndexInSegment, executionTokenIndexInSegment) {
			return nil
		}
	}

	return []rules.Finding{{
		Message:  "Staged download-and-execute flow detected",
		Position: downloadToken.Position,
	}}
}

func hasChainOperatorBetween(tokens []rules.Token, from int, to int) bool {
	if from < 0 || to < 0 || from >= len(tokens) || to >= len(tokens) {
		return false
	}
	if from > to {
		from, to = to, from
	}
	for i := from + 1; i < to; i++ {
		switch tokens[i].Value {
		case "|", ";", "&":
			return true
		}
	}
	return false
}
