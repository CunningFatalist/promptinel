package cmd

import (
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
	configFile string
	includes   []string
	excludes   []string
	apply      bool
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
		configFile: configFile,
		includes:   includes,
		excludes:   excludes,
		apply:      apply,
	}, nil
}

func runSanitizeWithOptions(args []string, options sanitizeOptions) error {
	cfg, err := config.Load(options.configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	files, err := collectSanitizeFiles(args, options.includes, options.excludes)
	if err != nil {
		return fmt.Errorf("collect files: %w", err)
	}

	changedFiles := 0
	skippedFiles := 0
	totalLineEndingChanges := 0
	totalZeroWidthChanges := 0

	for _, file := range files {
		info, statErr := os.Stat(file.AbsolutePath)
		if statErr != nil {
			return fmt.Errorf("stat file %q: %w", file.AbsolutePath, statErr)
		}

		if info.Size() > cfg.Limits.MaxFileSizeBytes {
			fmt.Printf("%s: skipped (size %d exceeds limits.max_file_size_bytes=%d)\n", file.RelativePath, info.Size(), cfg.Limits.MaxFileSizeBytes)
			skippedFiles++
			continue
		}

		content, readErr := os.ReadFile(file.AbsolutePath)
		if readErr != nil {
			return fmt.Errorf("read file %q: %w", file.AbsolutePath, readErr)
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
			if writeErr := os.WriteFile(file.AbsolutePath, []byte(result.Content), info.Mode().Perm()); writeErr != nil {
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

func collectSanitizeFiles(paths []string, includePatterns []string, excludePatterns []string) ([]sanitizeFile, error) {
	absolutePaths, err := collectFiles(paths)
	if err != nil {
		return nil, err
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

	return files, nil
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

		if walkErr := filepath.WalkDir(resolvedPath, func(currentPath string, entry fs.DirEntry, currentErr error) error {
			if currentErr != nil {
				return currentErr
			}
			if entry.IsDir() {
				return nil
			}
			files = appendUniqueFile(files, seen, currentPath)
			return nil
		}); walkErr != nil {
			return nil, fmt.Errorf("walk path %q: %w", path, walkErr)
		}
	}

	return files, nil
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
	sanitizeCmd.Flags().StringArray("include", nil, "Glob pattern to include (can be repeated)")
	sanitizeCmd.Flags().StringArray("exclude", nil, "Glob pattern to exclude (can be repeated)")
	sanitizeCmd.Flags().Bool("apply", false, "Apply sanitized output to files (default is dry-run preview)")
}
