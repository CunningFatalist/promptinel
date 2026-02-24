package lexer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Lexer_Graphemes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty input",
			input: "",
			want:  []string{},
		},
		{
			name:  "ascii letters",
			input: "abc",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "combining acute accent",
			input: "a" + "e\u0301" + "b",
			want:  []string{"a", "e\u0301", "b"},
		},
		{
			name:  "emoji single grapheme with skin tone",
			input: "👍🏽",
			want:  []string{"👍🏽"},
		},
		{
			name:  "family emoji zwj sequence",
			input: "👨‍👩‍👧‍👦",
			want:  []string{"👨‍👩‍👧‍👦"},
		},
		{
			name:  "flag emoji regional indicators",
			input: "🇺🇸",
			want:  []string{"🇺🇸"},
		},
		{
			name:  "newline remains separate grapheme",
			input: "a\nb",
			want:  []string{"a", "\n", "b"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Graphemes(tc.input))
		})
	}
}

func Test_Lexer_IsZeroWidth(t *testing.T) {
	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "zero width space", r: '\u200b', want: true},
		{name: "zero width non joiner", r: '\u200c', want: true},
		{name: "zero width joiner", r: '\u200d', want: true},
		{name: "byte order mark", r: '\ufeff', want: true},
		{name: "word joiner", r: '\u2060', want: true},
		{name: "regular space", r: ' ', want: false},
		{name: "tab", r: '\t', want: false},
		{name: "newline", r: '\n', want: false},
		{name: "letter", r: 'a', want: false},
		{name: "other invisible but not listed", r: '\u00ad', want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsZeroWidth(tc.r))
		})
	}
}

func Test_Lexer_IsControl(t *testing.T) {
	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "nul", r: '\x00', want: true},
		{name: "start of heading", r: '\x01', want: true},
		{name: "unit separator", r: '\x1f', want: true},
		{name: "newline excluded", r: '\n', want: false},
		{name: "tab excluded", r: '\t', want: false},
		{name: "space", r: ' ', want: false},
		{name: "delete not in range", r: '\x7f', want: false},
		{name: "letter", r: 'x', want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsControl(tc.r))
		})
	}
}
