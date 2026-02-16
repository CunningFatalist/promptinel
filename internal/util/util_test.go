package util

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Util_ExitOnError(t *testing.T) {
	envKey := "GOJO_EXIT_ON_ERROR_TEST"
	if os.Getenv(envKey) == "1" {
		ExitOnError("some error", errors.New("please do panic"))
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=Test_Util_ExitOnError")
	cmd.Env = append(os.Environ(), envKey+"=1")
	err := cmd.Run()

	var exitErr *exec.ExitError
	assert.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func Test_Util_ExitOnError_NoError(t *testing.T) {
	assert.NotPanics(t, func() {
		ExitOnError("no error", nil)
	})
}
