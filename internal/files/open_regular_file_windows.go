//go:build windows

package files

import "os"

func openFileNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNonRegular
	}

	return os.Open(path)
}
