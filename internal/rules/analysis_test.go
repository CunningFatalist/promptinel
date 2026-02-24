package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Rules_SegmentDocument_EmptyInput(t *testing.T) {
	segments := segmentDocument("")
	require.Len(t, segments, 1)
	assert.Equal(t, SegmentTypePlainText, segments[0].Type)
	assert.Equal(t, "", segments[0].Content)
	assert.Equal(t, 0, segments[0].ByteOffset)
	assert.Equal(t, Position{Line: 1, Column: 1}, segments[0].Position)
}

func Test_Rules_SegmentDocument_PlainTextOnly(t *testing.T) {
	content := "just plain text"
	segments := segmentDocument(content)
	require.Len(t, segments, 1)
	assert.Equal(t, SegmentTypePlainText, segments[0].Type)
	assert.Equal(t, content, segments[0].Content)
	assert.Equal(t, 0, segments[0].ByteOffset)
}

func Test_Rules_SegmentDocument_UnclosedTemplateFallsBackToPlainText(t *testing.T) {
	content := "before {{ missing close"
	segments := segmentDocument(content)
	require.Len(t, segments, 2)

	assert.Equal(t, SegmentTypePlainText, segments[0].Type)
	assert.Equal(t, "before ", segments[0].Content)
	assert.Equal(t, 0, segments[0].ByteOffset)

	assert.Equal(t, SegmentTypePlainText, segments[1].Type)
	assert.Equal(t, "{{ missing close", segments[1].Content)
	assert.Equal(t, 7, segments[1].ByteOffset)
}

func Test_Rules_SegmentDocument_MixedTemplateAndPlainText(t *testing.T) {
	content := "a {{x}} b <%y%> c ${z}"
	segments := segmentDocument(content)
	require.Len(t, segments, 6)

	assert.Equal(t, SegmentTypePlainText, segments[0].Type)
	assert.Equal(t, "a ", segments[0].Content)
	assert.Equal(t, SegmentTypeTemplate, segments[1].Type)
	assert.Equal(t, "{{x}}", segments[1].Content)
	assert.Equal(t, SegmentTypePlainText, segments[2].Type)
	assert.Equal(t, " b ", segments[2].Content)
	assert.Equal(t, SegmentTypeTemplate, segments[3].Type)
	assert.Equal(t, "<%y%>", segments[3].Content)
	assert.Equal(t, SegmentTypePlainText, segments[4].Type)
	assert.Equal(t, " c ", segments[4].Content)
	assert.Equal(t, SegmentTypeTemplate, segments[5].Type)
	assert.Equal(t, "${z}", segments[5].Content)
}

func Test_Rules_PositionTracker_PositionAt_MatchesPositionFromByteOffset(t *testing.T) {
	content := string([]byte("first line\nemoji: 😀\ninvalid:\xff\nend"))
	offsets := []int{-10, 0, 1, 5, 10, 11, 12, 18, 19, 20, 21, 22, 23, 24, 25, len(content) - 1, len(content), len(content) + 10}

	tracker := newPositionTracker(content)
	for _, offset := range offsets {
		expected := PositionFromByteOffset(content, offset)
		assert.Equal(t, expected, tracker.positionAt(offset), "offset=%d", offset)
	}
}

func Test_Rules_PositionTracker_PositionAt_RewindsForEarlierOffsets(t *testing.T) {
	content := "line1\nline2\nline3"
	tracker := newPositionTracker(content)

	_ = tracker.positionAt(len(content))
	assert.Equal(t, PositionFromByteOffset(content, 0), tracker.positionAt(0))
	assert.Equal(t, PositionFromByteOffset(content, 6), tracker.positionAt(6))
}
