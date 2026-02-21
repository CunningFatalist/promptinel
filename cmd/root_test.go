package cmd

import (
	"strings"
	"testing"
)

func Test_Cmd_RootCommand_PrintsDevelopmentVersion(t *testing.T) {
	previousVersion := Version
	t.Cleanup(func() {
		Version = previousVersion
	})

	Version = "development"
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
	previousVersion := Version
	t.Cleanup(func() {
		Version = previousVersion
		_ = rootCmd.Flags().Set("version", "false")
	})

	Version = "1.2.3"
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
