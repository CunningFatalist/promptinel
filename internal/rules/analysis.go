package rules

import (
	"strings"
	"unicode/utf8"

	"github.com/CunningFatalist/promptinel/internal/lexer"
)

type templateBoundary struct {
	open  string
	close string
}

var templateBoundaries = [...]templateBoundary{
	{open: "{{", close: "}}"},
	{open: "${", close: "}"},
	{open: "<%", close: "%>"},
}

func segmentDocument(content string) []Segment {
	if content == "" {
		return []Segment{{
			Type:       SegmentTypePlainText,
			Content:    "",
			Position:   PositionFromByteOffset(content, 0),
			ByteOffset: 0,
		}}
	}

	segments := make([]Segment, 0, len(content)/16+1)
	cursor := 0

	for cursor < len(content) {
		start, boundary, found := findNextTemplateStart(content, cursor)
		if !found {
			segments = append(segments, Segment{
				Type:       SegmentTypePlainText,
				Content:    content[cursor:],
				Position:   PositionFromByteOffset(content, cursor),
				ByteOffset: cursor,
			})
			break
		}

		if start > cursor {
			segments = append(segments, Segment{
				Type:       SegmentTypePlainText,
				Content:    content[cursor:start],
				Position:   PositionFromByteOffset(content, cursor),
				ByteOffset: cursor,
			})
		}

		searchFrom := start + len(boundary.open)
		closingRelative := strings.Index(content[searchFrom:], boundary.close)
		if closingRelative < 0 {
			segments = append(segments, Segment{
				Type:       SegmentTypePlainText,
				Content:    content[start:],
				Position:   PositionFromByteOffset(content, start),
				ByteOffset: start,
			})
			break
		}

		end := searchFrom + closingRelative + len(boundary.close)
		segments = append(segments, Segment{
			Type:       SegmentTypeTemplate,
			Content:    content[start:end],
			Position:   PositionFromByteOffset(content, start),
			ByteOffset: start,
		})
		cursor = end
	}

	return segments
}

func findNextTemplateStart(content string, cursor int) (int, templateBoundary, bool) {
	bestStart := len(content)
	var best templateBoundary
	found := false

	for _, boundary := range templateBoundaries {
		relative := strings.Index(content[cursor:], boundary.open)
		if relative < 0 {
			continue
		}
		start := cursor + relative
		if !found || start < bestStart {
			bestStart = start
			best = boundary
			found = true
		}
	}

	return bestStart, best, found
}

func tokenizeSegment(documentContent string, segment Segment) []Token {
	lexed := lexer.Classify(lexer.Lex(segment.Content))
	tokens := make([]Token, 0, len(lexed))
	tracker := newPositionTracker(documentContent)

	for _, token := range lexed {
		absoluteStart := segment.ByteOffset + token.Start
		absoluteEnd := segment.ByteOffset + token.End
		tokens = append(tokens, Token{
			Value:    token.Value,
			Type:     token.Type,
			Start:    absoluteStart,
			End:      absoluteEnd,
			Position: tracker.positionAt(absoluteStart),
		})
	}

	return tokens
}

// positionTracker maps byte offsets to line/column positions in amortized O(n)
// across a token stream. This avoids repeatedly rescanning from byte 0 for every token.
type positionTracker struct {
	content string
	index   int
	line    int
	column  int
}

func newPositionTracker(content string) *positionTracker {
	return &positionTracker{
		content: content,
		index:   0,
		line:    1,
		column:  1,
	}
}

// positionAt returns the 1-based line/column for byteOffset while advancing from
// the current cursor. Tokenization asks for non-decreasing offsets, so this stays
// linear overall; if a caller asks for an earlier offset, the tracker rewinds.
func (p *positionTracker) positionAt(byteOffset int) Position {
	if byteOffset < 0 {
		byteOffset = 0
	}
	if byteOffset > len(p.content) {
		byteOffset = len(p.content)
	}

	if byteOffset < p.index {
		p.index = 0
		p.line = 1
		p.column = 1
	}

	for p.index < byteOffset {
		r, size := utf8.DecodeRuneInString(p.content[p.index:])
		if r == utf8.RuneError && size == 1 {
			p.index++
			p.column++
			continue
		}
		p.index += size
		if r == '\n' {
			p.line++
			p.column = 1
			continue
		}
		p.column++
	}

	return Position{Line: p.line, Column: p.column}
}
