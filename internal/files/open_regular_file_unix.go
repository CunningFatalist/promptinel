//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package files

import (
	"errors"
	"os"
	"syscall"
)

func openFileNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlink
		}
		return nil, err
	}

	return os.NewFile(uintptr(fd), path), nil
}
