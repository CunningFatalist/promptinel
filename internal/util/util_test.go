package util

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/exitcode"
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

func Test_Util_ExitOnCommandError_DefaultCode(t *testing.T) {
	envKey := "GOJO_EXIT_ON_COMMAND_ERROR_DEFAULT_TEST"
	if os.Getenv(envKey) == "1" {
		ExitOnCommandError("some error", errors.New("boom"))
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=Test_Util_ExitOnCommandError_DefaultCode")
	cmd.Env = append(os.Environ(), envKey+"=1")
	err := cmd.Run()

	var exitErr *exec.ExitError
	assert.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func Test_Util_ExitOnCommandError_ExitCodeError(t *testing.T) {
	envKey := "GOJO_EXIT_ON_COMMAND_ERROR_CODE_TEST"
	if os.Getenv(envKey) == "1" {
		ExitOnCommandError("some error", exitcode.Error{Code: exitcode.CodeFail})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=Test_Util_ExitOnCommandError_ExitCodeError")
	cmd.Env = append(os.Environ(), envKey+"=1")
	err := cmd.Run()

	var exitErr *exec.ExitError
	assert.ErrorAs(t, err, &exitErr)
	assert.Equal(t, int(exitcode.CodeFail), exitErr.ExitCode())
}

func Test_Util_ExitOnCommandError_NoError(t *testing.T) {
	assert.NotPanics(t, func() {
		ExitOnCommandError("no error", nil)
	})
}

func Test_Util_PadRight(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		width    int
		expected string
	}{
		{
			name:     "pads shorter input",
			input:    "high",
			width:    6,
			expected: "high  ",
		},
		{
			name:     "returns unchanged when already max width",
			input:    "medium",
			width:    6,
			expected: "medium",
		},
		{
			name:     "returns unchanged when longer than width",
			input:    "critical",
			width:    6,
			expected: "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := PadRight(tt.input, tt.width)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
