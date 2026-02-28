package files

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/filters"
)

// CollectOptions defines behavior for file collection and skip reasons.
type CollectOptions struct {
	PathStatErrorPrefix  string
	SymlinkSkipReason    string
	NonRegularSkipReason string
	WalkMissingReason    string
	MetadataErrorReason  func(error) string
}

// ScanCollectOptions configures file collection behavior for scan workflows.
func ScanCollectOptions() CollectOptions {
	return CollectOptions{
		PathStatErrorPrefix:  "stat path",
		SymlinkSkipReason:    "symbolic links are not scanned",
		NonRegularSkipReason: "non-regular file",
		WalkMissingReason:    "path does not exist",
		MetadataErrorReason: func(err error) string {
			return fmt.Sprintf("metadata read failed (%v)", err)
		},
	}
}

// SanitizeCollectOptions configures file collection behavior for sanitize workflows.
func SanitizeCollectOptions() CollectOptions {
	return CollectOptions{
		PathStatErrorPrefix:  "lstat path",
		SymlinkSkipReason:    "symbolic links are not sanitized",
		NonRegularSkipReason: "non-regular file",
		MetadataErrorReason: func(err error) string {
			return fmt.Sprintf("metadata error: %v", err)
		},
	}
}

// SkippedPath captures a path skipped during collection.
type SkippedPath struct {
	Path   string
	Reason string
}

// TargetFile is a collected, filter-matched file path.
type TargetFile struct {
	AbsolutePath string
	RelativePath string
}

// SkippedTarget is a skipped path after filter matching.
type SkippedTarget struct {
	AbsolutePath string
	RelativePath string
	Reason       string
}

// Collect resolves paths into regular files, returning skipped entries for unsupported paths.
func Collect(inputPaths []string, options CollectOptions) ([]string, []SkippedPath, error) {
	files := make([]string, 0)
	skipped := make([]SkippedPath, 0)
	seen := make(map[string]struct{})

	for _, path := range inputPaths {
		resolvedPath, err := filepath.Abs(path)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve path %q: %w", path, err)
		}

		fileInfo, err := os.Lstat(resolvedPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s %q: %w", options.PathStatErrorPrefix, path, err)
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			skipped = append(skipped, SkippedPath{Path: resolvedPath, Reason: options.SymlinkSkipReason})
			continue
		}

		if !fileInfo.IsDir() {
			if !fileInfo.Mode().IsRegular() {
				skipped = append(skipped, SkippedPath{Path: resolvedPath, Reason: options.NonRegularSkipReason})
				continue
			}
			files = appendUniqueFile(files, seen, resolvedPath)
			continue
		}

		err = filepath.WalkDir(resolvedPath, func(currentPath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				reason := fmt.Sprintf("walk error: %v", walkErr)
				if options.WalkMissingReason != "" && errors.Is(walkErr, fs.ErrNotExist) {
					reason = options.WalkMissingReason
				}
				skipped = append(skipped, SkippedPath{Path: currentPath, Reason: reason})
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				skipped = append(skipped, SkippedPath{Path: currentPath, Reason: options.SymlinkSkipReason})
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				reason := fmt.Sprintf("metadata error: %v", infoErr)
				if options.MetadataErrorReason != nil {
					reason = options.MetadataErrorReason(infoErr)
				}
				skipped = append(skipped, SkippedPath{Path: currentPath, Reason: reason})
				return nil
			}
			if !info.Mode().IsRegular() {
				skipped = append(skipped, SkippedPath{Path: currentPath, Reason: options.NonRegularSkipReason})
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

// FilterPaths applies include/exclude patterns to collected files and skipped paths.
func FilterPaths(
	workingDir string,
	filePaths []string,
	skippedPaths []SkippedPath,
	includePatterns []string,
	excludePatterns []string,
) ([]TargetFile, []SkippedTarget) {
	files := make([]TargetFile, 0, len(filePaths))
	for _, absolutePath := range filePaths {
		relativePath := RelativePathFromWorkingDir(workingDir, absolutePath)
		if !filters.Match(relativePath, includePatterns, excludePatterns) {
			continue
		}
		files = append(files, TargetFile{
			AbsolutePath: absolutePath,
			RelativePath: relativePath,
		})
	}

	skipped := make([]SkippedTarget, 0, len(skippedPaths))
	for _, skippedPath := range skippedPaths {
		relativePath := RelativePathFromWorkingDir(workingDir, skippedPath.Path)
		if !filters.Match(relativePath, includePatterns, excludePatterns) {
			continue
		}
		skipped = append(skipped, SkippedTarget{
			AbsolutePath: skippedPath.Path,
			RelativePath: relativePath,
			Reason:       skippedPath.Reason,
		})
	}

	return files, skipped
}

// RelativePathFromWorkingDir resolves an absolute path relative to workingDir when possible.
func RelativePathFromWorkingDir(workingDir string, filePath string) string {
	if strings.TrimSpace(workingDir) == "" {
		return filePath
	}
	if relativePath, err := filepath.Rel(workingDir, filePath); err == nil {
		return relativePath
	}
	return filePath
}

func appendUniqueFile(paths []string, seen map[string]struct{}, path string) []string {
	cleanPath := filepath.Clean(path)
	canonicalPath := canonicalizePath(cleanPath)
	if _, exists := seen[canonicalPath]; exists {
		return paths
	}
	seen[canonicalPath] = struct{}{}
	return append(paths, cleanPath)
}

func canonicalizePath(path string) string {
	cleanPath := filepath.Clean(path)
	if resolvedPath, err := filepath.EvalSymlinks(cleanPath); err == nil {
		return filepath.Clean(resolvedPath)
	}
	return cleanPath
}
