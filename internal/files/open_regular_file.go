package files

import (
	"errors"
	"fmt"
	"os"
)

var (
	// ErrSymlink reports that the target resolved to a symbolic link.
	ErrSymlink = errors.New("symbolic link")
	// ErrNonRegular reports that the target resolved to a non-regular file.
	ErrNonRegular = errors.New("non-regular file")
)

// OpenRegularFile opens a regular file without following a final-path symlink
// when the platform supports it.
func OpenRegularFile(path string) (*os.File, os.FileInfo, error) {
	file, err := openFileNoFollow(path)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat open file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, ErrNonRegular
	}

	return file, info, nil
}
