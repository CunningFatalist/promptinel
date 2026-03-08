package helpers

import "testing"

func Test_RulesHelpers_UnicodeInfoLookups(t *testing.T) {
	t.Parallel()

	bidi, ok := BidiControlInfo('\u202e')
	if !ok || bidi.Name != "RIGHT-TO-LEFT OVERRIDE" || bidi.Class != "override" {
		t.Fatalf("unexpected bidi metadata: %#v ok=%v", bidi, ok)
	}

	formatting, ok := InvisibleFormattingInfo('\u200b')
	if !ok || formatting.Name != "ZERO WIDTH SPACE" || formatting.Class != "zero-width" {
		t.Fatalf("unexpected formatting metadata: %#v ok=%v", formatting, ok)
	}

	whitespace, ok := NonstandardWhitespaceInfo('\u00a0')
	if !ok || whitespace.Name != "NO-BREAK SPACE" || whitespace.Class != "whitespace" {
		t.Fatalf("unexpected whitespace metadata: %#v ok=%v", whitespace, ok)
	}

	if _, ok := BidiControlInfo('x'); ok {
		t.Fatal("expected regular rune not to have bidi metadata")
	}
	if _, ok := InvisibleFormattingInfo('x'); ok {
		t.Fatal("expected regular rune not to have formatting metadata")
	}
	if _, ok := NonstandardWhitespaceInfo('x'); ok {
		t.Fatal("expected regular rune not to have whitespace metadata")
	}
}

func Test_RulesHelpers_SurroundingNonWhitespaceToken(t *testing.T) {
	t.Parallel()

	content := "alpha beta\tgamma"

	token, start, end := SurroundingNonWhitespaceToken(content, 7)
	if token != "beta" || start != 6 || end != 10 {
		t.Fatalf("unexpected token range: token=%q start=%d end=%d", token, start, end)
	}

	token, start, end = SurroundingNonWhitespaceToken(content, -1)
	if token != "" || start != 0 || end != 0 {
		t.Fatalf("expected empty token for negative offset, got token=%q start=%d end=%d", token, start, end)
	}

	token, start, end = SurroundingNonWhitespaceToken(content, len(content))
	if token != "" || start != 0 || end != 0 {
		t.Fatalf("expected empty token for offset past end, got token=%q start=%d end=%d", token, start, end)
	}
}

func Test_RulesHelpers_LooksIdentifierLikeValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "too short", value: "ab", expected: false},
		{name: "url", value: "https://example.com", expected: true},
		{name: "email", value: "user@example.com", expected: true},
		{name: "path", value: "/tmp/file.txt", expected: true},
		{name: "dotted token", value: "config.yaml", expected: true},
		{name: "trailing dot", value: "config.", expected: false},
		{name: "home path", value: "~/file", expected: true},
		{name: "relative path", value: "./file", expected: true},
		{name: "digits", value: "token123", expected: true},
		{name: "trimmed punctuation", value: "\"example.com\"", expected: true},
		{name: "plain word", value: "promptinel", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if actual := LooksIdentifierLikeValue(tt.value); actual != tt.expected {
				t.Fatalf("expected %v for %q, got %v", tt.expected, tt.value, actual)
			}
		})
	}
}
