package lexer

import (
	"path/filepath"
	"strings"
	"unicode"
)

const (
	base64MinimumLength = 16
	base64Quantum       = 4
	maxBase64Padding    = 2
)

var urlPrefix = map[string]struct{}{
	"http":  {},
	"https": {},
	"ftp":   {},
	"ftps":  {},
	"sftp":  {},
	"file":  {},
	"ws":    {},
	"wss":   {},
}

var shellCommands = map[string]struct{}{
	"sh":         {},
	"bash":       {},
	"zsh":        {},
	"pwsh":       {},
	"powershell": {},
	"cmd":        {},
	"cmd.exe":    {},
	"curl":       {},
	"wget":       {},
	"ssh":        {},
	"scp":        {},
	"sftp":       {},
	"nc":         {},
	"netcat":     {},
	"telnet":     {},
}

// Classify upgrades lexical tokens into semantic token classes.
func Classify(tokens []Token) []Token {
	result := make([]Token, 0, len(tokens))

	for i := 0; i < len(tokens); i++ {
		t := tokens[i]

		if token, end, ok := classifyCodeBlock(tokens, i); ok {
			result = append(result, token)
			i = end
			continue
		}

		if token, end, ok := classifyURL(tokens, i); ok {
			result = append(result, token)
			i = end
			continue
		}

		if token, end, ok := classifyPlaceholder(tokens, i); ok {
			result = append(result, token)
			i = end
			continue
		}

		if token, end, ok := classifyBase64(tokens, i); ok {
			result = append(result, token)
			i = end
			continue
		}

		if t.Type == TokenWord || t.Type == TokenNumber {
			lower := strings.ToLower(t.Value)
			if _, ok := shellCommands[lower]; ok {
				t.Type = TokenShellCommand
			} else if looksLikeEmail(t.Value) {
				t.Type = TokenEmail
			} else if looksLikeBase64(t.Value) {
				t.Type = TokenBase64
			} else if looksLikePath(t.Value) {
				t.Type = TokenPath
			}
		}

		result = append(result, t)
	}

	return result
}

func classifyCodeBlock(tokens []Token, i int) (Token, int, bool) {
	if i+2 >= len(tokens) {
		return Token{}, 0, false
	}
	if tokens[i].Type != TokenSymbol || tokens[i].Value != "`" ||
		tokens[i+1].Type != TokenSymbol || tokens[i+1].Value != "`" ||
		tokens[i+2].Type != TokenSymbol || tokens[i+2].Value != "`" {
		return Token{}, 0, false
	}

	j := i + 3
	for j+2 < len(tokens) {
		if tokens[j].Type == TokenSymbol && tokens[j].Value == "`" &&
			tokens[j+1].Type == TokenSymbol && tokens[j+1].Value == "`" &&
			tokens[j+2].Type == TokenSymbol && tokens[j+2].Value == "`" {
			return Token{
				Type:  TokenCodeBlock,
				Value: join(tokens[i : j+3]),
				Start: tokens[i].Start,
				End:   tokens[j+2].End,
			}, j + 2, true
		}
		j++
	}

	return Token{}, 0, false
}

func classifyURL(tokens []Token, i int) (Token, int, bool) {
	if i+3 >= len(tokens) || tokens[i].Type != TokenWord {
		return Token{}, 0, false
	}
	if _, ok := urlPrefix[strings.ToLower(tokens[i].Value)]; !ok {
		return Token{}, 0, false
	}
	if tokens[i+1].Value != ":" || tokens[i+2].Value != "/" || tokens[i+3].Value != "/" {
		return Token{}, 0, false
	}

	j := i + 4
	for j < len(tokens) && tokens[j].Type != TokenWhitespace && tokens[j].Type != TokenNewline {
		j++
	}

	return Token{
		Type:  TokenURL,
		Value: join(tokens[i:j]),
		Start: tokens[i].Start,
		End:   tokens[j-1].End,
	}, j - 1, true
}

func classifyPlaceholder(tokens []Token, i int) (Token, int, bool) {
	if token, end, ok := classifyEnclosed(tokens, i, "${", "}"); ok {
		return token, end, true
	}
	if token, end, ok := classifyEnclosed(tokens, i, "{{", "}}"); ok {
		return token, end, true
	}
	if token, end, ok := classifyEnclosed(tokens, i, "<%", "%>"); ok {
		return token, end, true
	}
	return Token{}, 0, false
}

func classifyBase64(tokens []Token, i int) (Token, int, bool) {
	if i >= len(tokens) {
		return Token{}, 0, false
	}

	if tokens[i].Type != TokenWord && tokens[i].Type != TokenNumber {
		return Token{}, 0, false
	}

	end := i
	if i+1 < len(tokens) && tokens[i+1].Type == TokenSymbol && tokens[i+1].Value == "=" {
		end = i + 1
		if i+2 < len(tokens) && tokens[i+2].Type == TokenSymbol && tokens[i+2].Value == "=" {
			end = i + 2
		}
	}

	value := join(tokens[i : end+1])
	if !looksLikeBase64(value) {
		return Token{}, 0, false
	}

	return Token{
		Type:  TokenBase64,
		Value: value,
		Start: tokens[i].Start,
		End:   tokens[end].End,
	}, end, true
}

func classifyEnclosed(tokens []Token, i int, open string, close string) (Token, int, bool) {
	openLen := len(open)
	closeLen := len(close)
	if i+openLen-1 >= len(tokens) {
		return Token{}, 0, false
	}

	for k := 0; k < openLen; k++ {
		if tokens[i+k].Type != TokenSymbol || tokens[i+k].Value != string(open[k]) {
			return Token{}, 0, false
		}
	}

	j := i + openLen
	for j+closeLen-1 < len(tokens) {
		matched := true
		for k := 0; k < closeLen; k++ {
			if tokens[j+k].Type != TokenSymbol || tokens[j+k].Value != string(close[k]) {
				matched = false
				break
			}
		}
		if matched {
			end := j + closeLen - 1
			return Token{
				Type:  TokenPlaceholder,
				Value: join(tokens[i : end+1]),
				Start: tokens[i].Start,
				End:   tokens[end].End,
			}, end, true
		}
		j++
	}

	return Token{}, 0, false
}

func join(tokens []Token) string {
	if len(tokens) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(tokens[len(tokens)-1].End - tokens[0].Start)
	for _, token := range tokens {
		b.WriteString(token.Value)
	}
	return b.String()
}

func looksLikeEmail(value string) bool {
	at := strings.IndexByte(value, '@')
	dot := strings.LastIndexByte(value, '.')
	return at > 0 && dot > at+1 && dot < len(value)-1
}

func looksLikePath(value string) bool {
	if value == "." || value == ".." {
		return true
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return true
	}
	if strings.ContainsRune(value, filepath.Separator) {
		return true
	}
	return strings.Contains(value, `\`) && len(value) > 2
}

func looksLikeBase64(value string) bool {
	if len(value) < base64MinimumLength || len(value)%base64Quantum != 0 {
		return false
	}
	padding := 0
	for i, r := range value {
		if r == '=' {
			padding++
			if i < len(value)-maxBase64Padding {
				return false
			}
			continue
		}
		if padding > 0 {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+' && r != '/' {
			return false
		}
	}
	return true
}
