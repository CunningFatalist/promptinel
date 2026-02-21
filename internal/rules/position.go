package rules

// PositionFromByteOffset converts a byte offset into 1-based line/column values.
func PositionFromByteOffset(content string, byteOffset int) Position {
	if byteOffset < 0 {
		byteOffset = 0
	}
	if byteOffset > len(content) {
		byteOffset = len(content)
	}

	line := 1
	column := 1
	for i, r := range content {
		if i >= byteOffset {
			break
		}
		if r == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}

	return Position{Line: line, Column: column}
}
