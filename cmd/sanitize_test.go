package cmd

import (
	"strings"
	"testing"
)

func Test_Cmd_SanitizeCommand_PrintsPlaceholderOutput(t *testing.T) {
	output := captureStdout(t, func() {
		sanitizeCmd.Run(sanitizeCmd, nil)
	})

	if strings.TrimSpace(output) != "sanitize called" {
		t.Fatalf("expected sanitize output, got %q", output)
	}
}
