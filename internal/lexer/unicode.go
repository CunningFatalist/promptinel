package lexer

import "github.com/rivo/uniseg"

const (
	zeroWidthSpace         rune = 0x200B
	zeroWidthNonJoiner     rune = 0x200C
	zeroWidthJoiner        rune = 0x200D
	byteOrderMark          rune = 0xFEFF
	wordJoiner             rune = 0x2060
	asciiControlUpperBound rune = 32
	newlineRune            rune = '\n'
	horizontalTabRune      rune = '\t'
)

// Graphemes splits input into Unicode grapheme clusters.
func Graphemes(input string) []string {
	g := uniseg.NewGraphemes(input)

	result := make([]string, 0, len(input)/2)
	for g.Next() {
		result = append(result, g.Str())
	}

	return result
}

// IsZeroWidth returns true for invisible zero-width runes.
func IsZeroWidth(r rune) bool {
	switch r {
	case
		zeroWidthSpace,
		zeroWidthNonJoiner,
		zeroWidthJoiner,
		byteOrderMark,
		wordJoiner:
		return true
	}

	return false
}

// IsControl returns true for control characters except newline and tab.
func IsControl(r rune) bool {
	return r < asciiControlUpperBound && r != newlineRune && r != horizontalTabRune
}
