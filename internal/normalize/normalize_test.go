package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Normalize_ForScan_NormalizesLineEndingsWithoutStrippingZeroWidth(t *testing.T) {
	input := "a\r\nb\rc\u200bd"

	result := ForScan(input)

	assert.Equal(t, "a\nb\nc\u200bd", result.Content)
	assert.Equal(t, 2, result.LineEndingsNormalized)
	assert.Equal(t, 0, result.ZeroWidthRunesStripped)
}

func Test_Normalize_ForSanitize_StripsZeroWidthAndNormalizesLineEndings(t *testing.T) {
	input := "a\r\n\u200bb\u200c\r"

	result := ForSanitize(input)

	assert.Equal(t, "a\nb\n", result.Content)
	assert.Equal(t, 2, result.LineEndingsNormalized)
	assert.Equal(t, 2, result.ZeroWidthRunesStripped)
}

func Test_Normalize_Apply_KeepsInvalidUTF8Bytes(t *testing.T) {
	input := string([]byte{'a', 0xff, '\r', '\n'})

	result := Apply(input, Options{NormalizeLineEndings: true})

	assert.Equal(t, string([]byte{'a', 0xff, '\n'}), result.Content)
	assert.Equal(t, 1, result.LineEndingsNormalized)
}
