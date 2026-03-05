package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

func Test_SafeFile_ReplaceDestinationFile_ReturnsRenameErrorWhenTempFileMissing(t *testing.T) {
	workingDir := t.TempDir()
	err := replaceDestinationFile(filepath.Join(workingDir, "missing-temp-file"), filepath.Join(workingDir, "destination.txt"))
	if err == nil {
		t.Fatal("expected rename error for missing temp path")
	}
}
