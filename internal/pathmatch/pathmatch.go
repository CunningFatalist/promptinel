package pathmatch

import (
	"path/filepath"
	"strings"
)

// Match reports whether path matches pattern.
// It supports filepath.Match semantics and recursive "**" segments.
func Match(pattern string, path string) bool {
	normalizedPattern := normalize(pattern)
	normalizedPath := normalize(path)

	if matched, err := filepath.Match(normalizedPattern, normalizedPath); err == nil && matched {
		return true
	}

	patternParts := split(normalizedPattern)
	pathParts := split(normalizedPath)

	return matchSegments(patternParts, pathParts)
}

func normalize(value string) string {
	return strings.ReplaceAll(value, `\`, "/")
}

func split(value string) []string {
	trimmed := strings.Trim(value, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func matchSegments(patternParts []string, pathParts []string) bool {
	patternLen := len(patternParts)
	pathLen := len(pathParts)
	if patternLen == 0 {
		return pathLen == 0
	}

	dp := make([][]bool, patternLen+1)
	for i := range dp {
		dp[i] = make([]bool, pathLen+1)
	}
	dp[0][0] = true

	for i := 0; i < patternLen; i++ {
		segment := patternParts[i]
		if segment == "**" {
			for j := 0; j <= pathLen; j++ {
				if !dp[i][j] {
					continue
				}
				// "**" can match zero segments.
				dp[i+1][j] = true
				// Or consume one segment and keep matching with the same "**".
				if j < pathLen {
					dp[i][j+1] = true
				}
			}
			continue
		}

		for j := 0; j < pathLen; j++ {
			if !dp[i][j] {
				continue
			}
			matched, err := filepath.Match(segment, pathParts[j])
			if err != nil || !matched {
				continue
			}
			dp[i+1][j+1] = true
		}
	}

	return dp[patternLen][pathLen]
}
