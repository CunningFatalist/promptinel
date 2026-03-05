package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// AtomicWriteOptions controls atomic file replacement behavior.
type AtomicWriteOptions struct {
	TempPattern              string
	RefuseDestinationSymlink bool
}

// WriteFileAtomically writes content to a temporary file and atomically replaces the destination.
func WriteFileAtomically(path string, content []byte, perm os.FileMode, options AtomicWriteOptions) (returnErr error) {
	if options.RefuseDestinationSymlink {
		info, err := os.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("lstat destination: %w", err)
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symbolic link")
		}
	}

	tempPattern := options.TempPattern
	if tempPattern == "" {
		tempPattern = ".promptinel-*"
	}

	tempFile, err := os.CreateTemp(filepath.Dir(path), tempPattern)
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
	if err := replaceDestinationFile(tempPath, path); err != nil {
		return fmt.Errorf("replace destination file: %w", err)
	}

	return nil
}

func replaceDestinationFile(tempPath string, destinationPath string) error {
	renameErr := os.Rename(tempPath, destinationPath)
	if renameErr == nil {
		return nil
	}

	// On Windows, os.Rename cannot replace an existing destination.
	if runtime.GOOS != "windows" {
		return renameErr
	}

	if err := os.Remove(destinationPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove existing destination: %w", err)
	}
	if err := os.Rename(tempPath, destinationPath); err != nil {
		return err
	}
	return nil
}
