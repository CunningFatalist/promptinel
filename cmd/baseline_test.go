package cmd

import (
	"strings"
	"testing"
)

func Test_Cmd_BaselineCommand_PrintsPlaceholderOutput(t *testing.T) {
	output := captureStdout(t, func() {
		baselineCmd.Run(baselineCmd, nil)
	})

	if strings.TrimSpace(output) != "baseline called" {
		t.Fatalf("expected baseline output, got %q", output)
	}
}
