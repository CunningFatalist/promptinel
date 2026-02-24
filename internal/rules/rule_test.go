package rules

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Rules_PositionFromByteOffset_Bounds(t *testing.T) {
	content := "ab\ncd"

	pos := PositionFromByteOffset(content, -5)
	assert.Equal(t, Position{Line: 1, Column: 1}, pos)

	pos = PositionFromByteOffset(content, 100)
	assert.Equal(t, Position{Line: 2, Column: 3}, pos)
}

func Test_Rules_PositionFromByteOffset_Multiline(t *testing.T) {
	content := "first\nsecond\nthird"
	pos := PositionFromByteOffset(content, 8) // second line, 3rd column
	assert.Equal(t, Position{Line: 2, Column: 3}, pos)
}

func Test_Rules_Evaluate_SortsFindingsDeterministically(t *testing.T) {
	compiled := []CompiledRule{
		{
			ID:       "b",
			Severity: config.SeverityLow,
			checkDocument: func(_ Context, _ DocumentView) []Finding {
				return []Finding{{Message: "m2", Position: Position{Line: 2, Column: 1}}}
			},
		},
		{
			ID:       "a",
			Severity: config.SeverityHigh,
			checkDocument: func(_ Context, _ DocumentView) []Finding {
				return []Finding{
					{Message: "z", Position: Position{Line: 3, Column: 1}},
					{Message: "a", Position: Position{Line: 1, Column: 2}},
				}
			},
		},
	}

	findings := Evaluate(compiled, Context{}, "x")
	require.Len(t, findings, 3)
	assert.Equal(t, "a", findings[0].ID)
	assert.Equal(t, "a", findings[0].Message)
	assert.Equal(t, "a", findings[1].ID)
	assert.Equal(t, "z", findings[1].Message)
	assert.Equal(t, "b", findings[2].ID)
}

func Test_Rules_Evaluate_DispatchesPhaseChecks(t *testing.T) {
	docCalls := 0
	segmentCalls := 0
	tokenCalls := 0
	flowCalls := 0

	compiled := []CompiledRule{
		{
			ID:       "phase-rule",
			Severity: config.SeverityMedium,
			checkDocument: func(_ Context, _ DocumentView) []Finding {
				docCalls++
				return []Finding{{Message: "doc", Position: Position{Line: 1, Column: 1}}}
			},
			checkSegment: func(_ Context, segment Segment) []Finding {
				segmentCalls++
				if segment.Type != SegmentTypeTemplate {
					return nil
				}
				return []Finding{{Message: "segment", Position: segment.Position}}
			},
			checkTokens: func(_ Context, segment Segment, tokens []Token) []Finding {
				tokenCalls++
				if segment.Type != SegmentTypeTemplate || len(tokens) == 0 {
					return nil
				}
				return []Finding{{Message: "token", Position: tokens[0].Position}}
			},
			checkFlow: func(_ Context, doc AnalyzedDocument) []Finding {
				flowCalls++
				return []Finding{{
					Message:  "flow",
					Position: Position{Line: len(doc.Segments), Column: 1},
				}}
			},
		},
	}

	content := "before\n{{ exec(\"curl https://example.com\") }}\nafter"
	findings := Evaluate(compiled, Context{Path: "x.md"}, content)

	assert.Equal(t, 1, docCalls)
	assert.GreaterOrEqual(t, segmentCalls, 1)
	assert.GreaterOrEqual(t, tokenCalls, 1)
	assert.Equal(t, 1, flowCalls)
	require.Len(t, findings, 4)
	for _, finding := range findings {
		assert.Equal(t, "phase-rule", finding.ID)
		assert.Equal(t, config.SeverityMedium, finding.Severity)
	}
}

func Test_Rules_Evaluate_DocumentOnly_DoesNotBuildAnalysisArtifacts(t *testing.T) {
	compiled := []CompiledRule{
		{
			ID:       "doc-only",
			Severity: config.SeverityLow,
			checkDocument: func(_ Context, _ DocumentView) []Finding {
				return []Finding{{Message: "m", Position: Position{Line: 1, Column: 1}}}
			},
		},
	}

	findings := Evaluate(compiled, Context{}, "{{ content }}")
	require.Len(t, findings, 1)
	assert.Equal(t, "doc-only", findings[0].ID)
	assert.Equal(t, config.SeverityLow, findings[0].Severity)
}
