package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type stubTempFile struct {
	name      string
	chmodErr  error
	writeErr  error
	syncErr   error
	closeErr  error
	written   []byte
	closeCall int
}

func (s *stubTempFile) Name() string {
	return s.name
}

func (s *stubTempFile) Chmod(_ os.FileMode) error {
	return s.chmodErr
}

func (s *stubTempFile) Write(content []byte) (int, error) {
	s.written = append([]byte(nil), content...)
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(content), nil
}

func (s *stubTempFile) Sync() error {
	return s.syncErr
}

func (s *stubTempFile) Close() error {
	s.closeCall++
	return s.closeErr
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenDestinationLstatFails(t *testing.T) {
	originalLstat := lstatPath
	lstatPath = func(string) (os.FileInfo, error) {
		return nil, errors.New("forced lstat failure")
	}
	t.Cleanup(func() {
		lstatPath = originalLstat
	})

	err := WriteFileAtomically(filepath.Join(t.TempDir(), "file.txt"), []byte("content"), 0o644, AtomicWriteOptions{
		RefuseDestinationSymlink: true,
	})
	if err == nil {
		t.Fatal("expected lstat error")
	}
	if !strings.Contains(err.Error(), "lstat destination") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_SafeFile_WriteFileAtomically_OverwritesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("before"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	err := WriteFileAtomically(path, []byte("after"), 0o600, AtomicWriteOptions{TempPattern: ".safe-write-*"})
	if err != nil {
		t.Fatalf("write file atomically: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if string(content) != "after" {
		t.Fatalf("unexpected file content: %q", string(content))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replaced file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func Test_SafeFile_WriteFileAtomically_RefusesSymlinkDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	victimPath := filepath.Join(workingDir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("victim-original"), 0o644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}
	linkPath := filepath.Join(workingDir, "link.txt")
	if err := os.Symlink(victimPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	err := WriteFileAtomically(linkPath, []byte("replacement"), 0o644, AtomicWriteOptions{
		RefuseDestinationSymlink: true,
	})
	if err == nil {
		t.Fatal("expected symlink refusal error")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("unexpected error: %v", err)
	}

	victimContent, readErr := os.ReadFile(victimPath)
	if readErr != nil {
		t.Fatalf("read victim file: %v", readErr)
	}
	if string(victimContent) != "victim-original" {
		t.Fatalf("expected victim file unchanged, got %q", string(victimContent))
	}
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenDirectoryMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "file.txt")
	err := WriteFileAtomically(path, []byte("content"), 0o644, AtomicWriteOptions{})
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
	if !strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_SafeFile_WriteFileAtomically_CreatesNewFileWithDefaultOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")

	err := WriteFileAtomically(path, []byte("created"), 0o640, AtomicWriteOptions{})
	if err != nil {
		t.Fatalf("write file atomically: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read created file: %v", err)
	}
	if string(content) != "created" {
		t.Fatalf("unexpected file content: %q", string(content))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat created file: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("expected mode 0640, got %o", info.Mode().Perm())
	}
}

func Test_SafeFile_WriteFileAtomically_ReplacesSymlinkWhenRefusalDisabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	victimPath := filepath.Join(workingDir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("victim-original"), 0o644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}
	linkPath := filepath.Join(workingDir, "link.txt")
	if err := os.Symlink(victimPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	err := WriteFileAtomically(linkPath, []byte("replacement"), 0o600, AtomicWriteOptions{})
	if err != nil {
		t.Fatalf("write through symlink path: %v", err)
	}

	linkInfo, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat link path: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("expected symlink to be replaced with regular file, mode=%v", linkInfo.Mode())
	}

	linkContent, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatalf("read replacement file: %v", err)
	}
	if string(linkContent) != "replacement" {
		t.Fatalf("unexpected replacement file content: %q", string(linkContent))
	}

	victimContent, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("read victim file: %v", err)
	}
	if string(victimContent) != "victim-original" {
		t.Fatalf("expected victim file to remain unchanged, got %q", string(victimContent))
	}
}

func Test_SafeFile_ReplaceDestinationFile_ReturnsRenameErrorWhenTempFileMissing(t *testing.T) {
	workingDir := t.TempDir()
	err := replaceDestinationFile(filepath.Join(workingDir, "missing-temp-file"), filepath.Join(workingDir, "destination.txt"))
	if err == nil {
		t.Fatal("expected rename error for missing temp path")
	}
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenTempFileChmodFails(t *testing.T) {
	tempPath := filepath.Join(t.TempDir(), ".promptinel-temp")
	temp := &stubTempFile{name: tempPath, chmodErr: errors.New("forced chmod failure")}

	originalCreateTemp := createTempFile
	createTempFile = func(string, string) (tempFile, error) {
		return temp, nil
	}
	t.Cleanup(func() {
		createTempFile = originalCreateTemp
	})

	err := WriteFileAtomically(filepath.Join(t.TempDir(), "file.txt"), []byte("content"), 0o644, AtomicWriteOptions{})
	if err == nil {
		t.Fatal("expected chmod error")
	}
	if !strings.Contains(err.Error(), "set temp file permissions") {
		t.Fatalf("unexpected error: %v", err)
	}
	if temp.closeCall != 1 {
		t.Fatalf("expected temp file close on chmod failure, got %d", temp.closeCall)
	}
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenTempFileWriteFailsAndCleansUp(t *testing.T) {
	tempPath := filepath.Join(t.TempDir(), ".promptinel-temp")
	temp := &stubTempFile{name: tempPath, writeErr: errors.New("forced write failure")}
	if err := os.WriteFile(tempPath, []byte("temp"), 0o600); err != nil {
		t.Fatalf("seed temp path: %v", err)
	}

	originalCreateTemp := createTempFile
	createTempFile = func(string, string) (tempFile, error) {
		return temp, nil
	}
	t.Cleanup(func() {
		createTempFile = originalCreateTemp
	})

	err := WriteFileAtomically(filepath.Join(t.TempDir(), "file.txt"), []byte("content"), 0o644, AtomicWriteOptions{})
	if err == nil {
		t.Fatal("expected write error")
	}
	if !strings.Contains(err.Error(), "write temp file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(tempPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected temp path cleanup, stat error=%v", statErr)
	}
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenTempFileSyncFails(t *testing.T) {
	tempPath := filepath.Join(t.TempDir(), ".promptinel-temp")
	temp := &stubTempFile{name: tempPath, syncErr: errors.New("forced sync failure")}

	originalCreateTemp := createTempFile
	createTempFile = func(string, string) (tempFile, error) {
		return temp, nil
	}
	t.Cleanup(func() {
		createTempFile = originalCreateTemp
	})

	err := WriteFileAtomically(filepath.Join(t.TempDir(), "file.txt"), []byte("content"), 0o644, AtomicWriteOptions{})
	if err == nil {
		t.Fatal("expected sync error")
	}
	if !strings.Contains(err.Error(), "sync temp file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenTempFileCloseFails(t *testing.T) {
	tempPath := filepath.Join(t.TempDir(), ".promptinel-temp")
	temp := &stubTempFile{name: tempPath, closeErr: errors.New("forced close failure")}

	originalCreateTemp := createTempFile
	createTempFile = func(string, string) (tempFile, error) {
		return temp, nil
	}
	t.Cleanup(func() {
		createTempFile = originalCreateTemp
	})

	err := WriteFileAtomically(filepath.Join(t.TempDir(), "file.txt"), []byte("content"), 0o644, AtomicWriteOptions{})
	if err == nil {
		t.Fatal("expected close error")
	}
	if !strings.Contains(err.Error(), "close temp file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_SafeFile_WriteFileAtomically_ReturnsErrorWhenReplaceFailsAndCleansUp(t *testing.T) {
	tempPath := filepath.Join(t.TempDir(), ".promptinel-temp")
	temp := &stubTempFile{name: tempPath}
	if err := os.WriteFile(tempPath, []byte("temp"), 0o600); err != nil {
		t.Fatalf("seed temp path: %v", err)
	}

	originalCreateTemp := createTempFile
	originalRename := renamePath
	createTempFile = func(string, string) (tempFile, error) {
		return temp, nil
	}
	renamePath = func(string, string) error {
		return errors.New("forced rename failure")
	}
	t.Cleanup(func() {
		createTempFile = originalCreateTemp
		renamePath = originalRename
	})

	err := WriteFileAtomically(filepath.Join(t.TempDir(), "file.txt"), []byte("content"), 0o644, AtomicWriteOptions{})
	if err == nil {
		t.Fatal("expected replace error")
	}
	if !strings.Contains(err.Error(), "replace destination file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(tempPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected temp path cleanup, stat error=%v", statErr)
	}
}

func Test_SafeFile_ReplaceDestinationFile_WindowsRetrySucceeds(t *testing.T) {
	originalGOOS := currentGOOS
	originalRename := renamePath
	originalRemove := removePath
	currentGOOS = "windows"

	renameCalls := 0
	removedPath := ""
	renamePath = func(tempPath string, destinationPath string) error {
		renameCalls++
		if renameCalls == 1 {
			return errors.New("replace in use")
		}
		if tempPath == "" || destinationPath == "" {
			t.Fatal("expected populated rename paths")
		}
		return nil
	}
	removePath = func(path string) error {
		removedPath = path
		return nil
	}
	t.Cleanup(func() {
		currentGOOS = originalGOOS
		renamePath = originalRename
		removePath = originalRemove
	})

	err := replaceDestinationFile("temp.txt", "destination.txt")
	if err != nil {
		t.Fatalf("expected windows retry to succeed, got %v", err)
	}
	if renameCalls != 2 {
		t.Fatalf("expected two rename attempts, got %d", renameCalls)
	}
	if removedPath != "destination.txt" {
		t.Fatalf("unexpected remove path: %q", removedPath)
	}
}

func Test_SafeFile_ReplaceDestinationFile_WindowsReturnsRemoveError(t *testing.T) {
	originalGOOS := currentGOOS
	originalRename := renamePath
	originalRemove := removePath
	currentGOOS = "windows"
	renamePath = func(string, string) error {
		return errors.New("replace in use")
	}
	removePath = func(string) error {
		return errors.New("forced remove failure")
	}
	t.Cleanup(func() {
		currentGOOS = originalGOOS
		renamePath = originalRename
		removePath = originalRemove
	})

	err := replaceDestinationFile("temp.txt", "destination.txt")
	if err == nil {
		t.Fatal("expected remove error")
	}
	if !strings.Contains(err.Error(), "remove existing destination") {
		t.Fatalf("unexpected error: %v", err)
	}
}
