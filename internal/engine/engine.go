package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/files"
	"github.com/CunningFatalist/promptinel/internal/finding"
	"github.com/CunningFatalist/promptinel/internal/normalize"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const oversizedFileFindingID = finding.OversizedFileSkipID
const unreadableFileFindingID = finding.UnreadableFileSkipID

// Scanner evaluates configured rules against files.
type Scanner struct {
	compiledRules []rules.CompiledRule
	environment   config.Environment
	trustLevel    config.TrustLevel
	maxFileSize   int64
	config        *config.Config
}

// FileFinding links a finding with its source file.
type FileFinding = finding.FileFinding

// IsOversizedFileSkipFinding reports whether a finding indicates a file was skipped due to size.
func IsOversizedFileSkipFinding(fileFinding FileFinding) bool {
	return finding.IsOversizedFileSkip(fileFinding)
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetFiles, skippedTargets, err := files.CollectTargets(paths, files.ScanCollectOptions(), includePatterns, excludePatterns)
	if err != nil {
		return nil, err
	}

	scopeRoots := resolveScopeRoots(paths)
	findings := make([]FileFinding, 0, len(skippedTargets))
	for _, skippedPath := range skippedTargets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		findings = append(findings, FileFinding{
			Path: skippedPath.RelativePath,
			Finding: rules.Finding{
				ID:       unreadableFileFindingID,
				Severity: config.SeverityLow,
				Message:  fmt.Sprintf("File skipped: %s", skippedPath.Reason),
				Position: rules.Position{Line: 1, Column: 1},
			},
		})
	}

	targets := make([]scanTarget, 0, len(targetFiles))
	for _, filePath := range targetFiles {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		targets = append(targets, scanTarget{
			index:        len(targets),
			absolutePath: filePath.AbsolutePath,
			relativePath: filePath.RelativePath,
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

	workerCount := max(runtime.GOMAXPROCS(0), 1)
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	jobs := make(chan scanTarget)
	results := make(chan scanResult, len(targets))
	var workerGroup sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerGroup.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-jobs:
					if !ok {
						return
					}
					findings, err := s.scanSingleTarget(ctx, target, scopeRoots)
					select {
					case results <- scanResult{
						index:    target.index,
						findings: findings,
						err:      err,
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		})
	}

	scheduledCount := 0
	dispatchCanceled := false
	for _, target := range targets {
		select {
		case <-ctx.Done():
			dispatchCanceled = true
		case jobs <- target:
			scheduledCount++
		}
		if dispatchCanceled {
			break
		}
	}
	close(jobs)
	if dispatchCanceled {
		return nil, ctx.Err()
	}

	orderedFindings := make([][]FileFinding, len(targets))
	errsByIndex := make([]error, len(targets))
	for i := 0; i < scheduledCount; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			orderedFindings[result.index] = result.findings
			errsByIndex[result.index] = result.err
		}
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
	for _, ruleFinding := range ruleFindings {
		if scope != nil {
			ruleFinding.Severity = scope.Severity
		}
		findings = append(findings, FileFinding{
			Path:    target.relativePath,
			Finding: ruleFinding,
		})
	}

	return findings, nil
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
