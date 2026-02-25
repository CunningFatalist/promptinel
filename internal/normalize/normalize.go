package normalize

import (
	"strings"
	"unicode/utf8"

	"github.com/CunningFatalist/promptinel/internal/lexer"
)

// Options controls deterministic normalization behavior.
type Options struct {
	NormalizeLineEndings bool
	StripZeroWidth       bool
}

// Result contains normalized content and a summary of applied changes.
type Result struct {
	Content                string
	LineEndingsNormalized  int
	ZeroWidthRunesStripped int
}

// ForScan applies canonical normalization suitable for analysis.
func ForScan(content string) Result {
	return Apply(content, Options{
		NormalizeLineEndings: true,
		StripZeroWidth:       false,
	})
}

// ForSanitize applies safe transformations suitable for sanitize command output.
func ForSanitize(content string) Result {
	return Apply(content, Options{
		NormalizeLineEndings: true,
		StripZeroWidth:       true,
	})
}

// Apply normalizes content according to the provided options.
func Apply(content string, options Options) Result {
	if content == "" {
		return Result{Content: ""}
	}

	var builder strings.Builder
	builder.Grow(len(content))

	result := Result{}
	for i := 0; i < len(content); {
		if options.NormalizeLineEndings && content[i] == '\r' {
			if i+1 < len(content) && content[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			result.LineEndingsNormalized++
			builder.WriteByte('\n')
			continue
		}

		r, size := utf8.DecodeRuneInString(content[i:])
		if r == utf8.RuneError && size == 1 {
			builder.WriteByte(content[i])
			i++
			continue
		}

		if options.StripZeroWidth && lexer.IsZeroWidth(r) {
			result.ZeroWidthRunesStripped++
			i += size
			continue
		}

		builder.WriteString(content[i : i+size])
		i += size
	}

	result.Content = builder.String()
	return result
}
