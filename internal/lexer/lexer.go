package lexer

import (
	"unicode"
	"unicode/utf8"
)

const initialTokenCapacityDivisor = 4

// Lex tokenizes input in one pass while preserving byte offsets.
func Lex(input string) []Token {
	tokens := make([]Token, 0, len(input)/initialTokenCapacityDivisor)

	i := 0
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])

		if r == utf8.RuneError && size == 1 {
			tokens = append(tokens, Token{
				Type:  TokenControlChar,
				Value: input[i : i+size],
				Start: i,
				End:   i + size,
			})
			i += size
			continue
		}

		if IsZeroWidth(r) {
			tokens = append(tokens, Token{
				Type:  TokenZeroWidth,
				Value: input[i : i+size],
				Start: i,
				End:   i + size,
			})
			i += size
			continue
		}

		if IsControl(r) {
			tokens = append(tokens, Token{
				Type:  TokenControlChar,
				Value: input[i : i+size],
				Start: i,
				End:   i + size,
			})
			i += size
			continue
		}

		if r == '\n' {
			tokens = append(tokens, Token{
				Type:  TokenNewline,
				Value: "\n",
				Start: i,
				End:   i + size,
			})
			i += size
			continue
		}

		if unicode.IsSpace(r) {
			j := i + size
			for j < len(input) {
				r2, s2 := utf8.DecodeRuneInString(input[j:])
				if !unicode.IsSpace(r2) || r2 == '\n' {
					break
				}
				j += s2
			}

			tokens = append(tokens, Token{
				Type:  TokenWhitespace,
				Value: input[i:j],
				Start: i,
				End:   j,
			})
			i = j
			continue
		}

		if unicode.IsDigit(r) {
			j := i + size
			for j < len(input) {
				r2, s2 := utf8.DecodeRuneInString(input[j:])
				if !unicode.IsDigit(r2) && r2 != '_' && r2 != '.' {
					break
				}
				j += s2
			}
			tokens = append(tokens, Token{
				Type:  TokenNumber,
				Value: input[i:j],
				Start: i,
				End:   j,
			})
			i = j
			continue
		}

		if unicode.IsLetter(r) {
			j := i + size
			for j < len(input) {
				r2, s2 := utf8.DecodeRuneInString(input[j:])
				if !unicode.IsLetter(r2) && !unicode.IsDigit(r2) && r2 != '_' && r2 != '-' && r2 != '.' {
					break
				}
				j += s2
			}
			tokens = append(tokens, Token{
				Type:  TokenWord,
				Value: input[i:j],
				Start: i,
				End:   j,
			})
			i = j
			continue
		}

		tokens = append(tokens, Token{
			Type:  TokenSymbol,
			Value: input[i : i+size],
			Start: i,
			End:   i + size,
		})
		i += size
	}

	return tokens
}
