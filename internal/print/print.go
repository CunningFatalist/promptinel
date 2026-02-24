package print

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

// Message prints a simple message to the console.
func Message(message string) {
	fmt.Println(message)
}

// SuccessMessage prints a success message in green.
func SuccessMessage(message string) {
	color.Green(message)
}

// ErrorMessage prints an error message in red.
func ErrorMessage(message string) {
	_, _ = color.New(color.FgRed).Fprintln(os.Stderr, message)
}

// WarningMessage prints a warning message in yellow.
func WarningMessage(message string) {
	color.Yellow(message)
}
