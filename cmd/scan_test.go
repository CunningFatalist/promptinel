package cmd

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/exitcode"
	"github.com/spf13/cobra"
)

func Test_Cmd_ScanCommand_RequiresAtLeastOnePath(t *testing.T) {
	if err := scanCmd.Args(scanCmd, nil); err == nil {
		t.Fatal("expected error when no path arguments are provided")
	}
}

func Test_Cmd_ScanCommand_AcceptsPathArguments(t *testing.T) {
	if err := scanCmd.Args(scanCmd, []string{"prompts"}); err != nil {
		t.Fatalf("expected valid args, got error: %v", err)
	}
}

func Test_Cmd_ExitCodeError_ReturnsExpectedMessage(t *testing.T) {
	err := exitcode.Error{Code: exitcode.CodeFail}
	if err.Error() != "exit code 2" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func Test_Cmd_ScanOptionsFromCommand_ReadsFlagValues(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")

	if err := command.Flags().Set("config", "custom.yaml"); err != nil {
		t.Fatalf("set config flag: %v", err)
	}
	if err := command.Flags().Set("include", "*.md"); err != nil {
		t.Fatalf("set include flag: %v", err)
	}
	if err := command.Flags().Set("exclude", "*.txt"); err != nil {
		t.Fatalf("set exclude flag: %v", err)
	}

	options, err := scanOptionsFromCommand(command)
	if err != nil {
		t.Fatalf("read scan options: %v", err)
	}

	if options.configFile != "custom.yaml" {
		t.Fatalf("expected config file custom.yaml, got %q", options.configFile)
	}
	if len(options.includes) != 1 || options.includes[0] != "*.md" {
		t.Fatalf("unexpected includes: %#v", options.includes)
	}
	if len(options.excludes) != 1 || options.excludes[0] != "*.txt" {
		t.Fatalf("unexpected excludes: %#v", options.excludes)
	}
}
