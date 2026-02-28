package report

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func sanitizeForTerminal(value string) string {
	if value == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		switch {
		case r == '\n':
			builder.WriteString(`\n`)
		case r == '\r':
			builder.WriteString(`\r`)
		case r == '\t':
			builder.WriteString(`\t`)
		case isControlRune(r):
			builder.WriteString(`\x`)
			builder.WriteString(strconv.FormatInt(int64(r), 16))
		default:
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

func isControlRune(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	return unicode.IsControl(r)
}
