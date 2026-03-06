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

	downloadStage, hasDownload := firstStageToken(doc, isDownloadStage)
	if !hasDownload {
		return nil
	}

	transformStage, hasTransform := nextStageToken(doc, downloadStage.globalIndex+1, isTransformStage)
	executionStage, hasExecution := nextStageToken(doc, downloadStage.globalIndex+1, isExecutionStage)
	if !hasExecution {
		return nil
	}
	if hasTransform {
		execAfterTransform, ok := nextStageToken(doc, transformStage.globalIndex+1, isExecutionStage)
		if ok {
			executionStage = execAfterTransform
		}
	}
	if executionStage.globalIndex <= downloadStage.globalIndex {
		return nil
	}

	tokenDistance := executionStage.globalIndex - downloadStage.globalIndex
	if !hasTransform && downloadStage.segmentIndex == executionStage.segmentIndex && tokenDistance < minTokenDistanceForStagedFlow {
		return nil
	}
	if !hasTransform && downloadStage.segmentIndex == executionStage.segmentIndex {
		tokens := doc.TokensBySegment[downloadStage.segmentIndex]
		if hasChainOperatorBetween(tokens, downloadStage.indexInSegment, executionStage.indexInSegment) {
			return nil
		}
	}

	return []rules.Finding{{
		Message:  "Staged download-and-execute flow detected",
		Position: downloadStage.token.Position,
	}}
}

type stageToken struct {
	token          rules.Token
	globalIndex    int
	segmentIndex   int
	indexInSegment int
}

func firstStageToken(doc rules.AnalyzedDocument, matcher func(rules.Token, string) bool) (stageToken, bool) {
	return nextStageToken(doc, 0, matcher)
}

func nextStageToken(doc rules.AnalyzedDocument, from int, matcher func(rules.Token, string) bool) (stageToken, bool) {
	globalIndex := 0
	for segmentIndex, tokens := range doc.TokensBySegment {
		for indexInSegment := range tokens {
			token := tokens[indexInSegment]
			if globalIndex < from {
				globalIndex++
				continue
			}
			lower := strings.ToLower(token.Value)
			if matcher(token, lower) {
				return stageToken{
					token:          token,
					globalIndex:    globalIndex,
					segmentIndex:   segmentIndex,
					indexInSegment: indexInSegment,
				}, true
			}
			globalIndex++
		}
	}
	return stageToken{}, false
}

func isDownloadStage(_ rules.Token, lower string) bool {
	_, ok := signals.DownloadSignals[lower]
	return ok
}

func isTransformStage(_ rules.Token, lower string) bool {
	_, ok := signals.DecodeDecompressSignals[lower]
	return ok
}

func isExecutionStage(token rules.Token, lower string) bool {
	if token.Type == lexer.TokenShellCommand {
		_, ok := signals.ExecutionSignals[lower]
		return ok
	}
	_, ok := signals.ExecutionSignals[lower]
	return ok
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
