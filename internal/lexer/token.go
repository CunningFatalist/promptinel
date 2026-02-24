package lexer

// TokenType identifies lexical and semantic token categories.
type TokenType uint8

const (
	TokenUnknown TokenType = iota

	TokenWord
	TokenNumber
	TokenWhitespace
	TokenNewline
	TokenSymbol

	TokenURL
	TokenEmail
	TokenPath

	TokenString
	TokenCodeBlock

	TokenPlaceholder
	TokenBase64
	TokenShellCommand

	TokenZeroWidth
	TokenControlChar
)

// Token represents a lexical unit with byte offsets in the original content.
type Token struct {
	Type  TokenType
	Value string

	Start int
	End   int
}
