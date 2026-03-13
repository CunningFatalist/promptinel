package files

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func Test_Files_Collect_DeduplicatesOverlappingInputs(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("test"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	collected, skipped, err := Collect([]string{workingDir, file}, ScanCollectOptions())
	if err != nil {
		t.Fatalf("collect files: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	if len(collected) != 1 || collected[0] != file {
		t.Fatalf("expected one deduplicated file, got %#v", collected)
	}
}

func Test_Files_FilterPaths_ScanAndSanitizeMatchForEquivalentFilters(t *testing.T) {
	workingDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workingDir, "keep.md"), []byte("test"), 0o644); err != nil {
		t.Fatalf("write markdown file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, "skip.txt"), []byte("test"), 0o644); err != nil {
		t.Fatalf("write txt file: %v", err)
	}

	scanFiles, scanSkipped, err := Collect([]string{workingDir}, ScanCollectOptions())
	if err != nil {
		t.Fatalf("collect scan files: %v", err)
	}
	sanitizeFiles, sanitizeSkipped, err := Collect([]string{workingDir}, SanitizeCollectOptions())
	if err != nil {
		t.Fatalf("collect sanitize files: %v", err)
	}

	scanTargets, _ := FilterPaths(workingDir, scanFiles, scanSkipped, []string{"*.md"}, nil)
	sanitizeTargets, _ := FilterPaths(workingDir, sanitizeFiles, sanitizeSkipped, []string{"*.md"}, nil)

	if len(scanTargets) != 1 || len(sanitizeTargets) != 1 {
		t.Fatalf("expected one target each, scan=%#v sanitize=%#v", scanTargets, sanitizeTargets)
	}
	if scanTargets[0].RelativePath != sanitizeTargets[0].RelativePath {
		t.Fatalf("expected identical relative targets, scan=%q sanitize=%q", scanTargets[0].RelativePath, sanitizeTargets[0].RelativePath)
	}
}

func Test_Files_Collect_SkipsSymlinkWithModeSpecificReasons(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	target := filepath.Join(workingDir, "target.md")
	if err := os.WriteFile(target, []byte("test"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	link := filepath.Join(workingDir, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, scanSkipped, err := Collect([]string{link}, ScanCollectOptions())
	if err != nil {
		t.Fatalf("collect scan files: %v", err)
	}
	_, sanitizeSkipped, err := Collect([]string{link}, SanitizeCollectOptions())
	if err != nil {
		t.Fatalf("collect sanitize files: %v", err)
	}

	if len(scanSkipped) != 1 || scanSkipped[0].Reason != "symbolic links are not scanned" {
		t.Fatalf("unexpected scan skipped paths: %#v", scanSkipped)
	}
	if len(sanitizeSkipped) != 1 || sanitizeSkipped[0].Reason != "symbolic links are not sanitized" {
		t.Fatalf("unexpected sanitize skipped paths: %#v", sanitizeSkipped)
	}
}

func Test_Files_Collect_ReturnsConfiguredPathStatPrefix(t *testing.T) {
	_, _, err := Collect([]string{"/definitely/missing/path"}, ScanCollectOptions())
	if err == nil {
		t.Fatal("expected missing path error")
	}
	if !strings.Contains(err.Error(), "stat path") {
		t.Fatalf("expected stat path prefix in error, got %v", err)
	}

	_, _, err = Collect([]string{"/definitely/missing/path"}, SanitizeCollectOptions())
	if err == nil {
		t.Fatal("expected missing path error")
	}
	if !strings.Contains(err.Error(), "lstat path") {
		t.Fatalf("expected lstat path prefix in error, got %v", err)
	}
}

func Test_Files_CollectOptions_ReturnModeSpecificMessages(t *testing.T) {
	scanOptions := ScanCollectOptions()
	sanitizeOptions := SanitizeCollectOptions()

	if scanOptions.PathStatErrorPrefix != "stat path" {
		t.Fatalf("unexpected scan stat prefix: %#v", scanOptions)
	}
	if sanitizeOptions.PathStatErrorPrefix != "lstat path" {
		t.Fatalf("unexpected sanitize stat prefix: %#v", sanitizeOptions)
	}
	if scanOptions.SymlinkSkipReason != "symbolic links are not scanned" {
		t.Fatalf("unexpected scan symlink reason: %#v", scanOptions)
	}
	if sanitizeOptions.SymlinkSkipReason != "symbolic links are not sanitized" {
		t.Fatalf("unexpected sanitize symlink reason: %#v", sanitizeOptions)
	}
	if got := scanOptions.MetadataErrorReason(errors.New("boom")); got != "metadata read failed (boom)" {
		t.Fatalf("unexpected scan metadata error reason: %q", got)
	}
	if got := sanitizeOptions.MetadataErrorReason(errors.New("boom")); got != "metadata error: boom" {
		t.Fatalf("unexpected sanitize metadata error reason: %q", got)
	}
}

func Test_Files_Collect_SkipsNonRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are not supported in this test on windows")
	}

	workingDir := t.TempDir()
	pipePath := filepath.Join(workingDir, "test.fifo")
	if err := syscall.Mkfifo(pipePath, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}

	collected, skipped, err := Collect([]string{pipePath}, ScanCollectOptions())
	if err != nil {
		t.Fatalf("collect files: %v", err)
	}
	if len(collected) != 0 {
		t.Fatalf("expected no collected files, got %#v", collected)
	}
	if len(skipped) != 1 || skipped[0].Reason != "non-regular file" {
		t.Fatalf("expected one non-regular skip, got %#v", skipped)
	}
}

func Test_Files_Collect_SkipsSymlinkInsideDirectoryWalk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	target := filepath.Join(workingDir, "target.md")
	if err := os.WriteFile(target, []byte("test"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	link := filepath.Join(workingDir, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	collected, skipped, err := Collect([]string{workingDir}, ScanCollectOptions())
	if err != nil {
		t.Fatalf("collect files: %v", err)
	}
	if len(collected) != 1 || collected[0] != target {
		t.Fatalf("unexpected collected files: %#v", collected)
	}
	if len(skipped) != 1 || skipped[0].Path != link || skipped[0].Reason != "symbolic links are not scanned" {
		t.Fatalf("unexpected skipped files: %#v", skipped)
	}
}

func Test_Files_FilterPaths_AppliesIncludeExcludeToFilesAndSkipped(t *testing.T) {
	workingDir := t.TempDir()
	includePath := filepath.Join(workingDir, "keep.md")
	excludePath := filepath.Join(workingDir, "skip.txt")

	targets, skipped := FilterPaths(
		workingDir,
		[]string{includePath, excludePath},
		[]SkippedPath{
			{Path: includePath, Reason: "example"},
			{Path: excludePath, Reason: "example"},
		},
		[]string{"*.md"},
		[]string{"skip*"},
	)

	if len(targets) != 1 || targets[0].RelativePath != "keep.md" {
		t.Fatalf("unexpected filtered targets: %#v", targets)
	}
	if len(skipped) != 1 || skipped[0].RelativePath != "keep.md" {
		t.Fatalf("unexpected filtered skipped targets: %#v", skipped)
	}
}

func Test_Files_CollectTargets_CollectsAndFiltersInOneStep(t *testing.T) {
	workingDir := t.TempDir()
	includePath := filepath.Join(workingDir, "keep.md")
	excludePath := filepath.Join(workingDir, "skip.txt")
	if err := os.WriteFile(includePath, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write include file: %v", err)
	}
	if err := os.WriteFile(excludePath, []byte("skip"), 0o644); err != nil {
		t.Fatalf("write exclude file: %v", err)
	}

	targets, skipped, err := CollectTargets([]string{workingDir}, ScanCollectOptions(), []string{"*.md"}, nil)
	if err != nil {
		t.Fatalf("collect targets: %v", err)
	}

	if len(targets) != 1 || filepath.Base(targets[0].RelativePath) != "keep.md" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
	if len(skipped) != 0 {
		t.Fatalf("unexpected skipped targets: %#v", skipped)
	}
}

func Test_Files_OpenRegularFile_ReadsRegularFile(t *testing.T) {
	workingDir := t.TempDir()
	target := filepath.Join(workingDir, "file.md")
	if err := os.WriteFile(target, []byte("test"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	file, info, err := OpenRegularFile(target)
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
	})

	if !info.Mode().IsRegular() {
		t.Fatalf("expected regular file mode, got %v", info.Mode())
	}
}

func Test_Files_OpenRegularFile_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	target := filepath.Join(workingDir, "target.md")
	if err := os.WriteFile(target, []byte("test"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	link := filepath.Join(workingDir, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, _, err := OpenRegularFile(link)
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func Test_Files_OpenRegularFile_RejectsNonRegularFileWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are not supported in this test on windows")
	}

	workingDir := t.TempDir()
	pipePath := filepath.Join(workingDir, "test.fifo")
	if err := syscall.Mkfifo(pipePath, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := OpenRegularFile(pipePath)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNonRegular) {
			t.Fatalf("expected non-regular error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected non-regular open to return without blocking")
	}
}

func Test_Files_Collect_SkipsNonRegularFileDuringDirectoryWalk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are not supported in this test on windows")
	}

	workingDir := t.TempDir()
	regularPath := filepath.Join(workingDir, "keep.md")
	if err := os.WriteFile(regularPath, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	pipePath := filepath.Join(workingDir, "pipe.fifo")
	if err := syscall.Mkfifo(pipePath, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}

	collected, skipped, err := Collect([]string{workingDir}, ScanCollectOptions())
	if err != nil {
		t.Fatalf("collect files: %v", err)
	}
	if len(collected) != 1 || collected[0] != regularPath {
		t.Fatalf("unexpected collected files: %#v", collected)
	}
	if len(skipped) != 1 || skipped[0].Path != pipePath || skipped[0].Reason != "non-regular file" {
		t.Fatalf("unexpected skipped files: %#v", skipped)
	}
}

func Test_Files_RelativePathFromWorkingDir_ReturnsRelativeWhenPossible(t *testing.T) {
	workingDir := t.TempDir()
	absolutePath := filepath.Join(workingDir, "nested", "file.md")

	relative := RelativePathFromWorkingDir(workingDir, absolutePath)
	if relative != filepath.Join("nested", "file.md") {
		t.Fatalf("unexpected relative path: %q", relative)
	}
}

func Test_Files_RelativePathFromWorkingDir_ReturnsInputWhenWorkingDirEmpty(t *testing.T) {
	absolutePath := filepath.Join(t.TempDir(), "file.md")

	if relative := RelativePathFromWorkingDir("   ", absolutePath); relative != absolutePath {
		t.Fatalf("expected original path when working dir is empty, got %q", relative)
	}
}

func Test_Files_AppendUniqueFile_CanonicalizesPaths(t *testing.T) {
	workingDir := t.TempDir()
	path := filepath.Join(workingDir, "nested", "..", "file.md")

	seen := make(map[string]struct{})
	paths := appendUniqueFile(nil, seen, path)
	paths = appendUniqueFile(paths, seen, filepath.Clean(path))

	if len(paths) != 1 || paths[0] != filepath.Clean(path) {
		t.Fatalf("expected canonicalized deduplication, got %#v", paths)
	}
}

func Test_Files_CanonicalizePath_ReturnsCleanPathWhenSymlinkResolutionFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "..", "file.md")

	if canonical := canonicalizePath(path); canonical != filepath.Clean(path) {
		t.Fatalf("expected cleaned path fallback, got %q", canonical)
	}
}
