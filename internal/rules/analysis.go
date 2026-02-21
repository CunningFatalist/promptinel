package rules

import (
	"regexp"
	"strings"
)

var templateSegmentPattern = regexp.MustCompile(`\{\{[\s\S]*?\}\}|\$\{[\s\S]*?\}|<%[\s\S]*?%>`)
var tokenPattern = regexp.MustCompile(`https?://[^\s"'<>]+|{{|}}|\$\{|<%|%>|\|\||&&|[|&;(){}<>]|[A-Za-z0-9_./:+-]+`)
var base64LikePattern = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)

func segmentDocument(content string) []Segment {
	matches := templateSegmentPattern.FindAllStringIndex(content, -1)
	if len(matches) == 0 {
		return []Segment{
			{
				Type:       SegmentTypePlainText,
				Content:    content,
				Position:   PositionFromByteOffset(content, 0),
				ByteOffset: 0,
			},
		}
	}

	segments := make([]Segment, 0, len(matches)*2+1)
	cursor := 0
	for _, match := range matches {
		if match[0] > cursor {
			segments = append(segments, Segment{
				Type:       SegmentTypePlainText,
				Content:    content[cursor:match[0]],
				Position:   PositionFromByteOffset(content, cursor),
				ByteOffset: cursor,
			})
		}

		segments = append(segments, Segment{
			Type:       SegmentTypeTemplate,
			Content:    content[match[0]:match[1]],
			Position:   PositionFromByteOffset(content, match[0]),
			ByteOffset: match[0],
		})
		cursor = match[1]
	}

	if cursor < len(content) {
		segments = append(segments, Segment{
			Type:       SegmentTypePlainText,
			Content:    content[cursor:],
			Position:   PositionFromByteOffset(content, cursor),
			ByteOffset: cursor,
		})
	}

	return segments
}

func tokenizeSegment(documentContent string, segment Segment) []Token {
	matches := tokenPattern.FindAllStringIndex(segment.Content, -1)
	tokens := make([]Token, 0, len(matches))
	for _, match := range matches {
		value := segment.Content[match[0]:match[1]]
		byteOffset := segment.ByteOffset + match[0]
		tokens = append(tokens, Token{
			Value:    value,
			Kind:     classifyToken(value),
			Position: PositionFromByteOffset(documentContent, byteOffset),
		})
	}
	return tokens
}

func classifyToken(value string) TokenKind {
	lowered := strings.ToLower(value)

	switch {
	case strings.HasPrefix(lowered, "http://"), strings.HasPrefix(lowered, "https://"):
		return TokenKindURL
	case value == "{{" || value == "}}" || value == "${" || value == "<%" || value == "%>":
		return TokenKindPlaceholder
	case base64LikePattern.MatchString(value):
		return TokenKindBase64Like
	case isOperatorToken(value):
		return TokenKindOperator
	default:
		return TokenKindWord
	}
}

func isOperatorToken(value string) bool {
	switch value {
	case "|", "||", "&", "&&", ";", "(", ")", "{", "}", "<", ">":
		return true
	default:
		return false
	}
}
