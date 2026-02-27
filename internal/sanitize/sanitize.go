package sanitize

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/CunningFatalist/promptinel/internal/normalize"
)

// Request configures sanitize execution.
type Request struct {
	Paths      []string
	ConfigFile string
	Discover   bool
	Include    []string
	Exclude    []string
	IncludeSet bool
	ExcludeSet bool
	Apply      bool
}

// Action describes the per-file sanitize outcome.
type Action string

const (
	ActionSkipped       Action = "skipped"
	ActionWouldSanitize Action = "would_sanitize"
	ActionSanitized     Action = "sanitized"
)

// Event captures one emitted sanitize operation entry.
type Event struct {
	Path                   string
	Action                 Action
	Reason                 string
	LineEndingsNormalized  int
	ZeroWidthRunesStripped int
}

// Summary aggregates sanitize execution metrics.
type Summary struct {
	Files                  int
	Changed                int
	Skipped                int
	LineEndingsNormalized  int
	ZeroWidthRunesStripped int
	Applied                bool
}

// Result contains emitted events and summary metrics.
type Result struct {
	Events  []Event
	Summary Summary
}

// Run executes sanitize workflow.
func Run(req Request) (Result, error) {
	cfg, err := config.LoadWithOptions(req.ConfigFile, config.LoadOptions{Discover: req.Discover})
	if err != nil {
		return Result{}, fmt.Errorf("load config: %w", err)
	}

	includes, excludes := filters.ResolveEffective(cfg, req.Include, req.Exclude, req.IncludeSet, req.ExcludeSet)
	files, skippedDuringDiscovery, err := collectSanitizeFiles(req.Paths, includes, excludes)
	if err != nil {
		return Result{}, fmt.Errorf("collect files: %w", err)
	}

	result := Result{Events: make([]Event, 0, len(files)+len(skippedDuringDiscovery))}
	for _, skipped := range skippedDuringDiscovery {
		result.Events = append(result.Events, Event{Path: skipped.RelativePath, Action: ActionSkipped, Reason: skipped.Reason})
		result.Summary.Skipped++
	}

	for _, file := range files {
		info, statErr := os.Lstat(file.AbsolutePath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: "path no longer exists"})
				result.Summary.Skipped++
				continue
			}
			return Result{}, fmt.Errorf("lstat file %q: %w", file.AbsolutePath, statErr)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: "symbolic links are not sanitized"})
			result.Summary.Skipped++
			continue
		}
		if !info.Mode().IsRegular() {
			result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: "non-regular file"})
			result.Summary.Skipped++
			continue
		}

		if info.Size() > cfg.Limits.MaxFileSizeBytes {
			result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: fmt.Sprintf("size %d exceeds limits.max_file_size_bytes=%d", info.Size(), cfg.Limits.MaxFileSizeBytes)})
			result.Summary.Skipped++
			continue
		}

		content, readErr := os.ReadFile(file.AbsolutePath)
		if readErr != nil {
			result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: fmt.Sprintf("read error: %v", readErr)})
			result.Summary.Skipped++
			continue
		}

		normalized := normalize.ForSanitize(string(content))
		if normalized.Content == string(content) {
			continue
		}

		result.Summary.Changed++
		result.Summary.LineEndingsNormalized += normalized.LineEndingsNormalized
		result.Summary.ZeroWidthRunesStripped += normalized.ZeroWidthRunesStripped

		action := ActionWouldSanitize
		if req.Apply {
			latestInfo, latestErr := os.Lstat(file.AbsolutePath)
			if latestErr != nil {
				if errors.Is(latestErr, os.ErrNotExist) {
					result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: "path no longer exists"})
					result.Summary.Skipped++
					continue
				}
				return Result{}, fmt.Errorf("lstat file before write %q: %w", file.AbsolutePath, latestErr)
			}
			if latestInfo.Mode()&os.ModeSymlink != 0 {
				result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: "symbolic links are not sanitized"})
				result.Summary.Skipped++
				continue
			}
			if !latestInfo.Mode().IsRegular() {
				result.Events = append(result.Events, Event{Path: file.RelativePath, Action: ActionSkipped, Reason: "non-regular file"})
				result.Summary.Skipped++
				continue
			}
			if err := writeFileAtomically(file.AbsolutePath, []byte(normalized.Content), info.Mode().Perm()); err != nil {
				return Result{}, fmt.Errorf("write sanitized file %q: %w", file.AbsolutePath, err)
			}
			action = ActionSanitized
		}

		result.Events = append(result.Events, Event{
			Path:                   file.RelativePath,
			Action:                 action,
			LineEndingsNormalized:  normalized.LineEndingsNormalized,
			ZeroWidthRunesStripped: normalized.ZeroWidthRunesStripped,
		})
	}

	result.Summary.Files = len(files)
	result.Summary.Applied = req.Apply
	return result, nil
}

type sanitizeFile struct {
	AbsolutePath string
	RelativePath string
}

type sanitizeSkippedFile struct {
	AbsolutePath string
	RelativePath string
	Reason       string
}

func collectSanitizeFiles(paths []string, includePatterns []string, excludePatterns []string) ([]sanitizeFile, []sanitizeSkippedFile, error) {
	absolutePaths, skippedPaths, err := collectFiles(paths)
	if err != nil {
		return nil, nil, err
	}

	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = ""
	}

	files := make([]sanitizeFile, 0, len(absolutePaths))
	for _, absolutePath := range absolutePaths {
		relativePath := relativePathFromWorkingDir(workingDir, absolutePath)
		if !filters.Match(relativePath, includePatterns, excludePatterns) {
			continue
		}
		files = append(files, sanitizeFile{AbsolutePath: absolutePath, RelativePath: relativePath})
	}

	skippedFiles := make([]sanitizeSkippedFile, 0, len(skippedPaths))
	for _, skippedPath := range skippedPaths {
		relativePath := relativePathFromWorkingDir(workingDir, skippedPath.path)
		if !filters.Match(relativePath, includePatterns, excludePatterns) {
			continue
		}
		skippedFiles = append(skippedFiles, sanitizeSkippedFile{
			AbsolutePath: skippedPath.path,
			RelativePath: relativePath,
			Reason:       skippedPath.reason,
		})
	}

	return files, skippedFiles, nil
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
			return nil, nil, fmt.Errorf("lstat path %q: %w", path, err)
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			skipped = append(skipped, skippedPath{path: resolvedPath, reason: "symbolic links are not sanitized"})
			continue
		}

		if !fileInfo.IsDir() {
			if !fileInfo.Mode().IsRegular() {
				skipped = append(skipped, skippedPath{path: resolvedPath, reason: "non-regular file"})
				continue
			}
			files = appendUniqueFile(files, seen, resolvedPath)
			continue
		}

		walkErr := filepath.WalkDir(resolvedPath, func(currentPath string, entry fs.DirEntry, currentErr error) error {
			if currentErr != nil {
				skipped = append(skipped, skippedPath{path: currentPath, reason: fmt.Sprintf("walk error: %v", currentErr)})
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				skipped = append(skipped, skippedPath{path: currentPath, reason: "symbolic links are not sanitized"})
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				skipped = append(skipped, skippedPath{path: currentPath, reason: fmt.Sprintf("metadata error: %v", infoErr)})
				return nil
			}
			if !info.Mode().IsRegular() {
				skipped = append(skipped, skippedPath{path: currentPath, reason: "non-regular file"})
				return nil
			}
			files = appendUniqueFile(files, seen, currentPath)
			return nil
		})
		if walkErr != nil {
			return nil, nil, fmt.Errorf("walk path %q: %w", path, walkErr)
		}
	}

	return files, skipped, nil
}

func appendUniqueFile(files []string, seen map[string]struct{}, path string) []string {
	cleanPath := filepath.Clean(path)
	canonicalPath := cleanPath
	if resolvedPath, err := filepath.EvalSymlinks(cleanPath); err == nil {
		canonicalPath = filepath.Clean(resolvedPath)
	}
	if _, exists := seen[canonicalPath]; exists {
		return files
	}
	seen[canonicalPath] = struct{}{}
	return append(files, cleanPath)
}

func writeFileAtomically(path string, content []byte, perm os.FileMode) (returnErr error) {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, ".promptinel-sanitize-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	tempPath := tempFile.Name()
	defer func() {
		if returnErr != nil {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(perm); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("set temp file permissions: %w", err)
	}
	if _, err := tempFile.Write(content); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace destination file: %w", err)
	}

	return nil
}

func relativePathFromWorkingDir(workingDir string, filePath string) string {
	if strings.TrimSpace(workingDir) == "" {
		return filePath
	}
	if rel, err := filepath.Rel(workingDir, filePath); err == nil {
		return rel
	}
	return filePath
}
