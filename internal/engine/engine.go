package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/normalize"
	"github.com/CunningFatalist/promptinel/internal/pathmatch"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const oversizedFileFindingID = "scan-file-too-large"
const unreadableFileFindingID = "scan-file-unreadable"

// Scanner evaluates configured rules against files.
type Scanner struct {
	compiledRules []rules.CompiledRule
	environment   config.Environment
	trustLevel    config.TrustLevel
	maxFileSize   int64
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
	maxFileSize := config.DefaultMaxFileSizeBytes
	if cfg != nil {
		environment = cfg.Environment
		trustLevel = cfg.Trust.LocalFiles
		if cfg.Limits.MaxFileSizeBytes > 0 {
			maxFileSize = cfg.Limits.MaxFileSizeBytes
		}
	}

	return &Scanner{
		compiledRules: compiledRules,
		environment:   environment,
		trustLevel:    trustLevel,
		maxFileSize:   maxFileSize,
		config:        cfg,
	}
}

// ScanPaths scans provided files or directories and returns findings.
func (s *Scanner) ScanPaths(ctx context.Context, paths []string, includePatterns []string, excludePatterns []string) ([]FileFinding, error) {
	files, skippedPaths, err := collectFiles(paths)
	if err != nil {
		return nil, err
	}

	wd, err := os.Getwd()
	if err != nil {
		wd = ""
	}

	scopeRoots := resolveScopeRoots(paths)
	findings := make([]FileFinding, 0, len(skippedPaths))
	for _, skippedPath := range skippedPaths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		relativePath := relativePathFromWorkingDir(wd, skippedPath.path)
		if !matchesFilters(relativePath, includePatterns, excludePatterns) {
			continue
		}
		findings = append(findings, FileFinding{
			Path: relativePath,
			Finding: rules.Finding{
				ID:       unreadableFileFindingID,
				Severity: config.SeverityLow,
				Message:  fmt.Sprintf("File skipped: %s", skippedPath.reason),
				Position: rules.Position{Line: 1, Column: 1},
			},
		})
	}

	targets := make([]scanTarget, 0, len(files))
	for _, filePath := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		relativePath := relativePathFromWorkingDir(wd, filePath)
		if !matchesFilters(relativePath, includePatterns, excludePatterns) {
			continue
		}
		targets = append(targets, scanTarget{
			index:        len(targets),
			absolutePath: filePath,
			relativePath: relativePath,
		})
	}

	scannedFindings, err := s.scanTargets(ctx, targets, scopeRoots)
	if err != nil {
		return nil, err
	}

	findings = append(findings, scannedFindings...)
	return findings, nil
}

type scanTarget struct {
	index        int
	absolutePath string
	relativePath string
}

type scanResult struct {
	index    int
	findings []FileFinding
	err      error
}

func (s *Scanner) scanTargets(ctx context.Context, targets []scanTarget, scopeRoots []string) ([]FileFinding, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	workerCount := runtime.GOMAXPROCS(0)
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	jobs := make(chan scanTarget)
	results := make(chan scanResult, len(targets))
	var workerGroup sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			for target := range jobs {
				findings, err := s.scanSingleTarget(ctx, target, scopeRoots)
				results <- scanResult{
					index:    target.index,
					findings: findings,
					err:      err,
				}
			}
		}()
	}

	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	orderedFindings := make([][]FileFinding, len(targets))
	errsByIndex := make([]error, len(targets))
	for i := 0; i < len(targets); i++ {
		result := <-results
		orderedFindings[result.index] = result.findings
		errsByIndex[result.index] = result.err
	}

	workerGroup.Wait()

	for _, err := range errsByIndex {
		if err != nil {
			return nil, err
		}
	}

	findings := make([]FileFinding, 0)
	for _, bucket := range orderedFindings {
		findings = append(findings, bucket...)
	}

	return findings, nil
}

func (s *Scanner) scanSingleTarget(ctx context.Context, target scanTarget, scopeRoots []string) ([]FileFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(target.absolutePath)
	if err != nil {
		return []FileFinding{{
			Path: target.relativePath,
			Finding: rules.Finding{
				ID:       unreadableFileFindingID,
				Severity: config.SeverityLow,
				Message:  fmt.Sprintf("File skipped: metadata read failed (%v)", err),
				Position: rules.Position{Line: 1, Column: 1},
			},
		}}, nil
	}
	if fileInfo.Size() > s.maxFileSize {
		return []FileFinding{{
			Path: target.relativePath,
			Finding: rules.Finding{
				ID:       oversizedFileFindingID,
				Severity: config.SeverityLow,
				Message:  fmt.Sprintf("File skipped: size %d bytes exceeds limits.max_file_size_bytes (%d)", fileInfo.Size(), s.maxFileSize),
				Position: rules.Position{Line: 1, Column: 1},
			},
		}}, nil
	}

	content, err := os.ReadFile(target.absolutePath)
	if err != nil {
		return []FileFinding{{
			Path: target.relativePath,
			Finding: rules.Finding{
				ID:       unreadableFileFindingID,
				Severity: config.SeverityLow,
				Message:  fmt.Sprintf("File skipped: read failed (%v)", err),
				Position: rules.Position{Line: 1, Column: 1},
			},
		}}, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	normalized := normalize.ForScan(string(content))

	ruleFindings := rules.Evaluate(s.compiledRules, rules.Context{
		Path:        target.relativePath,
		Environment: s.environment,
		TrustLevel:  s.trustLevel,
	}, normalized.Content)

	scope := s.scopeForFile(target.relativePath, target.absolutePath, scopeRoots)
	findings := make([]FileFinding, 0, len(ruleFindings))
	for _, finding := range ruleFindings {
		if scope != nil {
			finding.Severity = scope.Severity
		}
		findings = append(findings, FileFinding{
			Path:    target.relativePath,
			Finding: finding,
		})
	}

	return findings, nil
}

func relativePathFromWorkingDir(workingDir string, filePath string) string {
	relativePath := filePath
	if workingDir == "" {
		return relativePath
	}
	if rel, err := filepath.Rel(workingDir, filePath); err == nil {
		return rel
	}
	return relativePath
}

type skippedPath struct {
	path   string
	reason string
}

func collectFiles(inputPaths []string) ([]string, []skippedPath, error) {
	files := make([]string, 0)
	skipped := make([]skippedPath, 0)
	seen := make(map[string]struct{})
	for _, path := range inputPaths {
		resolvedPath, err := filepath.Abs(path)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve path %q: %w", path, err)
		}

		fileInfo, err := os.Lstat(resolvedPath)
		if err != nil {
			return nil, nil, fmt.Errorf("stat path %q: %w", path, err)
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			skipped = append(skipped, skippedPath{
				path:   resolvedPath,
				reason: "symbolic links are not scanned",
			})
			continue
		}

		if !fileInfo.IsDir() {
			if !fileInfo.Mode().IsRegular() {
				skipped = append(skipped, skippedPath{
					path:   resolvedPath,
					reason: "non-regular file",
				})
				continue
			}
			files = appendUniqueFile(files, seen, resolvedPath)
			continue
		}

		err = filepath.WalkDir(resolvedPath, func(currentPath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, fs.ErrNotExist) {
					skipped = append(skipped, skippedPath{
						path:   currentPath,
						reason: "path does not exist",
					})
					return nil
				}
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: fmt.Sprintf("walk error: %v", walkErr),
				})
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: "symbolic links are not scanned",
				})
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: fmt.Sprintf("metadata read failed (%v)", infoErr),
				})
				return nil
			}
			if !info.Mode().IsRegular() {
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: "non-regular file",
				})
				return nil
			}
			files = appendUniqueFile(files, seen, currentPath)
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walk path %q: %w", path, err)
		}
	}
	return files, skipped, nil
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
