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
	if len(patternParts) == 0 {
		return len(pathParts) == 0
	}

	current := patternParts[0]
	if current == "**" {
		if len(patternParts) == 1 {
			return true
		}
		for i := 0; i <= len(pathParts); i++ {
			if matchSegments(patternParts[1:], pathParts[i:]) {
				return true
			}
		}
		return false
	}

	if len(pathParts) == 0 {
		return false
	}

	matched, err := filepath.Match(current, pathParts[0])
	if err != nil || !matched {
		return false
	}

	return matchSegments(patternParts[1:], pathParts[1:])
}
