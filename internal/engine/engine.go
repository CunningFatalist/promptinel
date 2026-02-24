package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/pathmatch"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

// Scanner evaluates configured rules against files.
type Scanner struct {
	compiledRules []rules.CompiledRule
	environment   config.Environment
	trustLevel    config.TrustLevel
	config        *config.Config
}

// FileFinding links a finding with its source file.
type FileFinding struct {
	Path string
	rules.Finding
}

// NewScanner creates a scanner from compiled rules and configuration.
func NewScanner(compiledRules []rules.CompiledRule, cfg *config.Config) *Scanner {
	environment := config.Environment{}
	trustLevel := config.TrustLevelTrusted
	if cfg != nil {
		environment = cfg.Environment
		trustLevel = cfg.Trust.LocalFiles
	}

	return &Scanner{
		compiledRules: compiledRules,
		environment:   environment,
		trustLevel:    trustLevel,
		config:        cfg,
	}
}

// ScanPaths scans provided files or directories and returns findings.
func (s *Scanner) ScanPaths(ctx context.Context, paths []string, includePatterns []string, excludePatterns []string) ([]FileFinding, error) {
	files, err := collectFiles(paths)
	if err != nil {
		return nil, err
	}

	scopeRoots := resolveScopeRoots(paths)
	findings := make([]FileFinding, 0)
	for _, filePath := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		relativePath := filePath
		if wd, err := os.Getwd(); err == nil {
			if rel, relErr := filepath.Rel(wd, filePath); relErr == nil {
				relativePath = rel
			}
		}
		if !matchesFilters(relativePath, includePatterns, excludePatterns) {
			continue
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read file %q: %w", filePath, err)
		}

		ruleFindings := rules.Evaluate(s.compiledRules, rules.Context{
			Path:        relativePath,
			Environment: s.environment,
			TrustLevel:  s.trustLevel,
		}, string(content))
		for _, finding := range ruleFindings {
			if scope := s.scopeForFile(relativePath, filePath, scopeRoots); scope != nil {
				finding.Severity = scope.Severity
			}
			findings = append(findings, FileFinding{
				Path:    relativePath,
				Finding: finding,
			})
		}
	}

	return findings, nil
}

func collectFiles(inputPaths []string) ([]string, error) {
	files := make([]string, 0)
	seen := make(map[string]struct{})
	for _, path := range inputPaths {
		resolvedPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve path %q: %w", path, err)
		}

		fileInfo, err := os.Stat(resolvedPath)
		if err != nil {
			return nil, fmt.Errorf("stat path %q: %w", path, err)
		}

		if !fileInfo.IsDir() {
			files = appendUniqueFile(files, seen, resolvedPath)
			continue
		}

		err = filepath.WalkDir(resolvedPath, func(currentPath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			files = appendUniqueFile(files, seen, currentPath)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk path %q: %w", path, err)
		}
	}
	return files, nil
}

func appendUniqueFile(files []string, seen map[string]struct{}, path string) []string {
	cleanPath := filepath.Clean(path)
	canonicalPath := canonicalizePath(cleanPath)
	if _, exists := seen[canonicalPath]; exists {
		return files
	}
	seen[canonicalPath] = struct{}{}
	return append(files, cleanPath)
}

func canonicalizePath(path string) string {
	cleanPath := filepath.Clean(path)
	if resolvedPath, err := filepath.EvalSymlinks(cleanPath); err == nil {
		return filepath.Clean(resolvedPath)
	}
	return cleanPath
}

func matchesFilters(path string, includePatterns []string, excludePatterns []string) bool {
	included := len(includePatterns) == 0
	for _, include := range includePatterns {
		if matchesPattern(include, path) {
			included = true
			break
		}
	}
	if !included {
		return false
	}

	for _, exclude := range excludePatterns {
		if matchesPattern(exclude, path) {
			return false
		}
	}

	return true
}

func matchesPattern(pattern string, path string) bool {
	if pathmatch.Match(pattern, path) {
		return true
	}
	if pathmatch.Match(pattern, filepath.Base(path)) {
		return true
	}
	return false
}

func (s *Scanner) scopeForPath(path string) *config.Scope {
	if s == nil || s.config == nil {
		return nil
	}
	return s.config.GetScopeForPath(path)
}

func (s *Scanner) scopeForFile(relativePath string, absolutePath string, roots []string) *config.Scope {
	if scope := s.scopeForPath(relativePath); scope != nil {
		return scope
	}

	for _, root := range roots {
		candidate, ok := relativeToRoot(root, absolutePath)
		if !ok {
			continue
		}
		if scope := s.scopeForPath(candidate); scope != nil {
			return scope
		}
	}

	return nil
}

func resolveScopeRoots(paths []string) []string {
	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}

		root := absPath
		if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
			root = filepath.Dir(absPath)
		}
		roots = append(roots, filepath.Clean(root))
	}
	return roots
}

func relativeToRoot(root string, absolutePath string) (string, bool) {
	rel, err := filepath.Rel(root, absolutePath)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return rel, true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}
