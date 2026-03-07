package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/rules"
)

var (
	skillMarkdownLinkPattern = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	skillPathPattern         = regexp.MustCompile(`(?:^|[\s"'` + "`" + `([])(\.?/)?((?:scripts|references|assets)/[^\s"'` + "`" + `)\]]*)`)
)

type skillResourceReference struct {
	path       string
	byteOffset int
}

func deriveSkillContext(absolutePath string, content string) *rules.SkillContext {
	if filepath.Base(absolutePath) != "SKILL.md" {
		return nil
	}

	skillDir := filepath.Dir(absolutePath)
	references := collectSkillResourceReferences(content)
	if len(references) == 0 {
		return nil
	}

	resolvedPaths := make([]string, 0, len(references))
	firstOffset := -1
	seen := make(map[string]struct{}, len(references))
	for _, reference := range references {
		cleaned, ok := normalizeSkillReference(reference.path)
		if !ok {
			continue
		}

		resolvedPath := filepath.Join(skillDir, filepath.FromSlash(cleaned))
		info, err := os.Stat(resolvedPath)
		if err != nil || info == nil {
			continue
		}

		if _, exists := seen[cleaned]; exists {
			if firstOffset == -1 || reference.byteOffset < firstOffset {
				firstOffset = reference.byteOffset
			}
			continue
		}
		seen[cleaned] = struct{}{}
		resolvedPaths = append(resolvedPaths, filepath.ToSlash(cleaned))
		if firstOffset == -1 || reference.byteOffset < firstOffset {
			firstOffset = reference.byteOffset
		}
	}

	if len(resolvedPaths) == 0 {
		return nil
	}

	slices.Sort(resolvedPaths)

	return &rules.SkillContext{
		ReferencedResources: resolvedPaths,
		ReferencePosition:   rules.PositionFromByteOffset(content, firstOffset),
	}
}

func collectSkillResourceReferences(content string) []skillResourceReference {
	references := make([]skillResourceReference, 0)

	linkMatches := skillMarkdownLinkPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range linkMatches {
		if len(match) < 4 {
			continue
		}
		references = append(references, skillResourceReference{
			path:       content[match[2]:match[3]],
			byteOffset: match[2],
		})
	}

	pathMatches := skillPathPattern.FindAllStringSubmatchIndex(content, -1)
	for _, match := range pathMatches {
		if len(match) < 8 {
			continue
		}

		pathStart := match[6]
		pathEnd := match[7]
		if pathStart < 0 || pathEnd < 0 {
			continue
		}

		references = append(references, skillResourceReference{
			path:       content[pathStart:pathEnd],
			byteOffset: pathStart,
		})
	}

	return references
}

func normalizeSkillReference(reference string) (string, bool) {
	trimmed := strings.TrimSpace(reference)
	if trimmed == "" {
		return "", false
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return "", false
	}
	if strings.HasPrefix(trimmed, "#") {
		return "", false
	}

	if marker := strings.IndexAny(trimmed, "?#"); marker >= 0 {
		trimmed = trimmed[:marker]
	}
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return "", false
	}

	normalized := filepath.ToSlash(filepath.Clean(trimmed))
	if normalized == "." || normalized == ".." {
		return "", false
	}
	if strings.HasPrefix(normalized, "/") {
		return "", false
	}
	if strings.HasPrefix(normalized, "../") {
		return "", false
	}
	if normalized == "scripts" || normalized == "references" || normalized == "assets" {
		return "", false
	}
	if after, ok := strings.CutPrefix(normalized, "./"); ok {
		normalized = after
	}
	if !strings.HasPrefix(normalized, "scripts/") && !strings.HasPrefix(normalized, "references/") && !strings.HasPrefix(normalized, "assets/") {
		return "", false
	}

	return normalized, true
}
