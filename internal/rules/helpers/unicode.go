package helpers

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// HiddenRune describes a suspicious invisible or directionality-affecting rune.
type HiddenRune struct {
	Name  string
	Class string
}

var bidiControlDetails = map[rune]HiddenRune{
	'\u061c': {Name: "ARABIC LETTER MARK", Class: "mark"},
	'\u200e': {Name: "LEFT-TO-RIGHT MARK", Class: "mark"},
	'\u200f': {Name: "RIGHT-TO-LEFT MARK", Class: "mark"},
	'\u202a': {Name: "LEFT-TO-RIGHT EMBEDDING", Class: "embedding"},
	'\u202b': {Name: "RIGHT-TO-LEFT EMBEDDING", Class: "embedding"},
	'\u202c': {Name: "POP DIRECTIONAL FORMATTING", Class: "formatting"},
	'\u202d': {Name: "LEFT-TO-RIGHT OVERRIDE", Class: "override"},
	'\u202e': {Name: "RIGHT-TO-LEFT OVERRIDE", Class: "override"},
	'\u2066': {Name: "LEFT-TO-RIGHT ISOLATE", Class: "isolate"},
	'\u2067': {Name: "RIGHT-TO-LEFT ISOLATE", Class: "isolate"},
	'\u2068': {Name: "FIRST STRONG ISOLATE", Class: "isolate"},
	'\u2069': {Name: "POP DIRECTIONAL ISOLATE", Class: "isolate"},
}

var invisibleFormattingDetails = map[rune]HiddenRune{
	'\u00ad': {Name: "SOFT HYPHEN", Class: "formatting"},
	'\u034f': {Name: "COMBINING GRAPHEME JOINER", Class: "formatting"},
	'\u180e': {Name: "MONGOLIAN VOWEL SEPARATOR", Class: "formatting"},
	'\u200b': {Name: "ZERO WIDTH SPACE", Class: "zero-width"},
	'\u200c': {Name: "ZERO WIDTH NON-JOINER", Class: "zero-width"},
	'\u200d': {Name: "ZERO WIDTH JOINER", Class: "zero-width"},
	'\u2060': {Name: "WORD JOINER", Class: "formatting"},
	'\ufeff': {Name: "BYTE ORDER MARK", Class: "zero-width"},
}

var nonstandardWhitespaceDetails = map[rune]HiddenRune{
	'\u0085': {Name: "NEXT LINE", Class: "whitespace"},
	'\u00a0': {Name: "NO-BREAK SPACE", Class: "whitespace"},
	'\u1680': {Name: "OGHAM SPACE MARK", Class: "whitespace"},
	'\u2000': {Name: "EN QUAD", Class: "whitespace"},
	'\u2001': {Name: "EM QUAD", Class: "whitespace"},
	'\u2002': {Name: "EN SPACE", Class: "whitespace"},
	'\u2003': {Name: "EM SPACE", Class: "whitespace"},
	'\u2004': {Name: "THREE-PER-EM SPACE", Class: "whitespace"},
	'\u2005': {Name: "FOUR-PER-EM SPACE", Class: "whitespace"},
	'\u2006': {Name: "SIX-PER-EM SPACE", Class: "whitespace"},
	'\u2007': {Name: "FIGURE SPACE", Class: "whitespace"},
	'\u2008': {Name: "PUNCTUATION SPACE", Class: "whitespace"},
	'\u2009': {Name: "THIN SPACE", Class: "whitespace"},
	'\u200a': {Name: "HAIR SPACE", Class: "whitespace"},
	'\u202f': {Name: "NARROW NO-BREAK SPACE", Class: "whitespace"},
	'\u205f': {Name: "MEDIUM MATHEMATICAL SPACE", Class: "whitespace"},
	'\u3000': {Name: "IDEOGRAPHIC SPACE", Class: "whitespace"},
}

// BidiControlInfo returns metadata for known bidi control runes.
func BidiControlInfo(r rune) (HiddenRune, bool) {
	detail, ok := bidiControlDetails[r]
	return detail, ok
}

// InvisibleFormattingInfo returns metadata for invisible formatting runes.
func InvisibleFormattingInfo(r rune) (HiddenRune, bool) {
	detail, ok := invisibleFormattingDetails[r]
	return detail, ok
}

// NonstandardWhitespaceInfo returns metadata for uncommon whitespace runes.
func NonstandardWhitespaceInfo(r rune) (HiddenRune, bool) {
	detail, ok := nonstandardWhitespaceDetails[r]
	return detail, ok
}

// SurroundingNonWhitespaceToken returns the contiguous non-whitespace token that contains byteOffset.
func SurroundingNonWhitespaceToken(content string, byteOffset int) (string, int, int) {
	if byteOffset < 0 || byteOffset >= len(content) {
		return "", 0, 0
	}

	start := byteOffset
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(content[:start])
		if unicode.IsSpace(r) {
			break
		}
		start -= size
	}

	end := byteOffset
	for end < len(content) {
		r, size := utf8.DecodeRuneInString(content[end:])
		if unicode.IsSpace(r) {
			break
		}
		end += size
	}

	return content[start:end], start, end
}

// LooksIdentifierLikeValue returns true for tokens that look like URLs, paths, emails, or identifiers.
func LooksIdentifierLikeValue(value string) bool {
	trimmed := strings.Trim(value, `"'()[]{}<>`)
	if len(trimmed) < 3 {
		return false
	}
	if strings.Contains(trimmed, "://") {
		return true
	}
	if strings.ContainsAny(trimmed, `/\@%?=&`) {
		return true
	}
	if strings.Contains(trimmed, ".") && !strings.HasSuffix(trimmed, ".") {
		return true
	}
	if strings.ContainsAny(trimmed, "_-") {
		return true
	}
	if strings.HasPrefix(trimmed, "~") || strings.HasPrefix(trimmed, ".") {
		return true
	}
	hasLower := false
	hasUpper := false
	for _, r := range trimmed {
		if unicode.IsDigit(r) {
			return true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return true
	}
	return false
}
