package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/normalize"
	"github.com/CunningFatalist/promptinel/internal/pathmatch"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

type sanitizeOptions struct {
	configFile        string
	noConfigDiscovery bool
	includes          []string
	excludes          []string
	apply             bool
}

// sanitizeCmd represents the sanitize command.
var sanitizeCmd = &cobra.Command{
	Use:   "sanitize [path ...]",
	Short: "Sanitize prompt files with safe, deterministic transformations",
	Long: `Sanitize prompt files using only safe transformations, such as removing invisible characters.

Examples:
  promptinel sanitize prompts/
  promptinel sanitize --apply prompts/
  promptinel sanitize --config .promptinel.yaml --apply prompts/
  promptinel sanitize --include "*.md" --apply prompts/
  promptinel sanitize --exclude "*.yaml" --apply prompts/`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("sanitize command failed", runSanitize(cmd, args))
	},
}

func runSanitize(cmd *cobra.Command, args []string) error {
	options, err := sanitizeOptionsFromCommand(cmd)
	if err != nil {
		return fmt.Errorf("read sanitize options: %w", err)
	}

	return runSanitizeWithOptions(args, options)
}

func sanitizeOptionsFromCommand(cmd *cobra.Command) (sanitizeOptions, error) {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read config flag: %w", err)
	}
	noConfigDiscovery, err := cmd.Flags().GetBool("no-config-discovery")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read no-config-discovery flag: %w", err)
	}

	includes, err := cmd.Flags().GetStringArray("include")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read include flag: %w", err)
	}

	excludes, err := cmd.Flags().GetStringArray("exclude")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read exclude flag: %w", err)
	}

	apply, err := cmd.Flags().GetBool("apply")
	if err != nil {
		return sanitizeOptions{}, fmt.Errorf("read apply flag: %w", err)
	}

	if err := validateGlobPatterns("include", includes); err != nil {
		return sanitizeOptions{}, err
	}
	if err := validateGlobPatterns("exclude", excludes); err != nil {
		return sanitizeOptions{}, err
	}

	return sanitizeOptions{
		configFile:        configFile,
		noConfigDiscovery: noConfigDiscovery,
		includes:          includes,
		excludes:          excludes,
		apply:             apply,
	}, nil
}

func runSanitizeWithOptions(args []string, options sanitizeOptions) error {
	cfg, err := config.LoadWithOptions(options.configFile, config.LoadOptions{
		Discover: !options.noConfigDiscovery,
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	files, skippedDuringDiscovery, err := collectSanitizeFiles(args, options.includes, options.excludes)
	if err != nil {
		return fmt.Errorf("collect files: %w", err)
	}

	changedFiles := 0
	skippedFiles := 0
	totalLineEndingChanges := 0
	totalZeroWidthChanges := 0

	for _, skipped := range skippedDuringDiscovery {
		fmt.Printf("%s: skipped (%s)\n", skipped.RelativePath, skipped.Reason)
		skippedFiles++
	}

	for _, file := range files {
		info, statErr := os.Lstat(file.AbsolutePath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				fmt.Printf("%s: skipped (path no longer exists)\n", file.RelativePath)
				skippedFiles++
				continue
			}
			return fmt.Errorf("lstat file %q: %w", file.AbsolutePath, statErr)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Printf("%s: skipped (symbolic links are not sanitized)\n", file.RelativePath)
			skippedFiles++
			continue
		}
		if !info.Mode().IsRegular() {
			fmt.Printf("%s: skipped (non-regular file)\n", file.RelativePath)
			skippedFiles++
			continue
		}

		if info.Size() > cfg.Limits.MaxFileSizeBytes {
			fmt.Printf("%s: skipped (size %d exceeds limits.max_file_size_bytes=%d)\n", file.RelativePath, info.Size(), cfg.Limits.MaxFileSizeBytes)
			skippedFiles++
			continue
		}

		content, readErr := os.ReadFile(file.AbsolutePath)
		if readErr != nil {
			fmt.Printf("%s: skipped (read error: %v)\n", file.RelativePath, readErr)
			skippedFiles++
			continue
		}

		result := normalize.ForSanitize(string(content))
		if result.Content == string(content) {
			continue
		}

		changedFiles++
		totalLineEndingChanges += result.LineEndingsNormalized
		totalZeroWidthChanges += result.ZeroWidthRunesStripped

		action := "would sanitize"
		if options.apply {
			latestInfo, latestErr := os.Lstat(file.AbsolutePath)
			if latestErr != nil {
				if errors.Is(latestErr, os.ErrNotExist) {
					fmt.Printf("%s: skipped (path no longer exists)\n", file.RelativePath)
					skippedFiles++
					continue
				}
				return fmt.Errorf("lstat file before write %q: %w", file.AbsolutePath, latestErr)
			}
			if latestInfo.Mode()&os.ModeSymlink != 0 {
				fmt.Printf("%s: skipped (symbolic links are not sanitized)\n", file.RelativePath)
				skippedFiles++
				continue
			}
			if !latestInfo.Mode().IsRegular() {
				fmt.Printf("%s: skipped (non-regular file)\n", file.RelativePath)
				skippedFiles++
				continue
			}
				if writeErr := writeFileAtomically(file.AbsolutePath, []byte(result.Content), info.Mode().Perm()); writeErr != nil {
					return fmt.Errorf("write sanitized file %q: %w", file.AbsolutePath, writeErr)
				}
				action = "sanitized"
			}

		fmt.Printf(
			"%s: %s (line_endings=%d, zero_width=%d)\n",
			file.RelativePath,
			action,
			result.LineEndingsNormalized,
			result.ZeroWidthRunesStripped,
		)
	}

	fmt.Printf("\nSummary: files=%d changed=%d skipped=%d line_endings=%d zero_width=%d\n",
		len(files),
		changedFiles,
		skippedFiles,
		totalLineEndingChanges,
		totalZeroWidthChanges,
	)
	if changedFiles > 0 && !options.apply {
		fmt.Println("Re-run with --apply to persist changes.")
	}

	return nil
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
		if !matchesFilters(relativePath, includePatterns, excludePatterns) {
			continue
		}
		files = append(files, sanitizeFile{
			AbsolutePath: absolutePath,
			RelativePath: relativePath,
		})
	}

	skippedFiles := make([]sanitizeSkippedFile, 0, len(skippedPaths))
	for _, skippedPath := range skippedPaths {
		relativePath := relativePathFromWorkingDir(workingDir, skippedPath.path)
		if !matchesFilters(relativePath, includePatterns, excludePatterns) {
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
			skipped = append(skipped, skippedPath{
				path:   resolvedPath,
				reason: "symbolic links are not sanitized",
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

		if walkErr := filepath.WalkDir(resolvedPath, func(currentPath string, entry fs.DirEntry, currentErr error) error {
			if currentErr != nil {
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: fmt.Sprintf("walk error: %v", currentErr),
				})
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: "symbolic links are not sanitized",
				})
				return nil
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				skipped = append(skipped, skippedPath{
					path:   currentPath,
					reason: fmt.Sprintf("metadata error: %v", infoErr),
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
		}); walkErr != nil {
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

func relativePathFromWorkingDir(workingDir string, filePath string) string {
	if strings.TrimSpace(workingDir) == "" {
		return filePath
	}
	if rel, err := filepath.Rel(workingDir, filePath); err == nil {
		return rel
	}
	return filePath
}

func init() {
	rootCmd.AddCommand(sanitizeCmd)
	sanitizeCmd.Flags().String("config", "", "Path to a Promptinel config file")
	sanitizeCmd.Flags().Bool("no-config-discovery", false, "Disable implicit .promptinel.yaml discovery from current directory and $HOME")
	sanitizeCmd.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	sanitizeCmd.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
	sanitizeCmd.Flags().Bool("apply", false, "Apply sanitized output to files (default is dry-run preview)")
}
