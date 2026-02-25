package helpers

import "github.com/CunningFatalist/promptinel/internal/rules"

// AdvancePositionByByteOffset advances a starting position by traversing up to
// byteOffset bytes in content.
func AdvancePositionByByteOffset(start rules.Position, content string, byteOffset int) rules.Position {
	if byteOffset < 0 {
		byteOffset = 0
	}
	if byteOffset > len(content) {
		byteOffset = len(content)
	}

	position := start
	for i, r := range content {
		if i >= byteOffset {
			break
		}
		if r == '\n' {
			position.Line++
			position.Column = 1
			continue
		}
		position.Column++
	}

	return position
}
