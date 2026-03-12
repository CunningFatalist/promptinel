package cmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	internalversion "github.com/CunningFatalist/promptinel/internal/version"
	"github.com/spf13/cobra"
)

func Test_Cmd_RootCommand_PrintsDevelopmentVersion(t *testing.T) {
	previousVersion := internalversion.BuildVersion
	t.Cleanup(func() {
		internalversion.BuildVersion = previousVersion
	})

	internalversion.BuildVersion = internalversion.Development
	output := captureStdout(t, func() {
		rootCmd.Run(rootCmd, nil)
	})

	if strings.TrimSpace(output) != "" {
		t.Fatalf("expected no output without version flag, got %q", output)
	}

	if err := rootCmd.Flags().Set("version", "true"); err != nil {
		t.Fatalf("set version flag: %v", err)
	}
	t.Cleanup(func() {
		_ = rootCmd.Flags().Set("version", "false")
	})

	output = captureStdout(t, func() {
		rootCmd.Run(rootCmd, nil)
	})

	if strings.TrimSpace(output) != "development" {
		t.Fatalf("expected development version output, got %q", output)
	}
}

func Test_Cmd_RootCommand_PrintsReleaseVersion(t *testing.T) {
	previousVersion := internalversion.BuildVersion
	t.Cleanup(func() {
		internalversion.BuildVersion = previousVersion
		_ = rootCmd.Flags().Set("version", "false")
	})

	internalversion.BuildVersion = "1.2.3"
	if err := rootCmd.Flags().Set("version", "true"); err != nil {
		t.Fatalf("set version flag: %v", err)
	}

	output := captureStdout(t, func() {
		rootCmd.Run(rootCmd, nil)
	})

	if strings.TrimSpace(output) != "v1.2.3" {
		t.Fatalf("expected release version output, got %q", output)
	}
}

func Test_Cmd_RootCommand_PrintsReleaseVersionWithVPrefix(t *testing.T) {
	previousVersion := internalversion.BuildVersion
	t.Cleanup(func() {
		internalversion.BuildVersion = previousVersion
		_ = rootCmd.Flags().Set("version", "false")
	})

	internalversion.BuildVersion = "v1.2.3"
	if err := rootCmd.Flags().Set("version", "true"); err != nil {
		t.Fatalf("set version flag: %v", err)
	}

	output := captureStdout(t, func() {
		rootCmd.Run(rootCmd, nil)
	})

	if strings.TrimSpace(output) != "v1.2.3" {
		t.Fatalf("expected release version output, got %q", output)
	}
}

func Test_Cmd_Execute_PrintsVersion(t *testing.T) {
	previousVersion := internalversion.BuildVersion
	t.Cleanup(func() {
		internalversion.BuildVersion = previousVersion
		rootCmd.SetArgs(nil)
		_ = rootCmd.Flags().Set("version", "false")
	})

	internalversion.BuildVersion = "1.2.3"
	rootCmd.SetArgs([]string{"--version"})

	output := captureStdout(t, func() {
		Execute()
	})
	if !strings.Contains(output, "v1.2.3") {
		t.Fatalf("expected version output, got %q", output)
	}
}

func Test_Cmd_Execute_ExitsOnInvalidArguments(t *testing.T) {
	envKey := "PROMPTINEL_TEST_EXECUTE_INVALID_ARGS"
	if os.Getenv(envKey) == "1" {
		rootCmd.SetArgs([]string{"--definitely-invalid-flag"})
		Execute()
		return
	}

	command := exec.Command(os.Args[0], "-test.run=Test_Cmd_Execute_ExitsOnInvalidArguments")
	command.Env = append(os.Environ(), envKey+"=1")
	output, err := command.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected non-zero exit error, got err=%v output=%q", err, string(output))
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d output=%q", exitErr.ExitCode(), string(output))
	}
	if !strings.Contains(string(output), "command execution failed") {
		t.Fatalf("expected command execution failure output, got %q", string(output))
	}
}

func Test_Cmd_DisplayVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{name: "development", version: internalversion.Development, expected: internalversion.Development},
		{name: "release", version: "1.2.3", expected: "v1.2.3"},
		{name: "already prefixed", version: "v1.2.3", expected: "v1.2.3"},
	}

	previousVersion := internalversion.BuildVersion
	t.Cleanup(func() {
		internalversion.BuildVersion = previousVersion
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internalversion.BuildVersion = tt.version
			if actual := displayVersion(); actual != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, actual)
			}
		})
	}
}

func Test_Cmd_ParseRootOptions_ReturnsErrorWhenFlagMissing(t *testing.T) {
	_, err := parseRootOptions(&cobra.Command{})
	if err == nil {
		t.Fatal("expected missing version flag error")
	}
}
