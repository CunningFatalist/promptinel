package util

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/CunningFatalist/promptinel/internal/print"
)

func ExitOnError(msg string, err error) {
	if err != nil {
		print.ErrorMessage(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1)
	}
}

// ExitOnCommandError prints a command error and exits with the mapped process code.
func ExitOnCommandError(msg string, err error) {
	if err == nil {
		return
	}

	print.ErrorMessage(fmt.Sprintf("%s: %v", msg, err))

	var codeErr exitcode.Error
	if ok := errors.As(err, &codeErr); ok {
		os.Exit(int(codeErr.Code))
	}

	os.Exit(1)
}

// PadRight pads text with trailing spaces to match width.
func PadRight(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}
