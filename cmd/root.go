package cmd

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/util"
	internalversion "github.com/CunningFatalist/promptinel/internal/version"
	"github.com/spf13/cobra"
)

type rootOptions struct {
	showVersion bool
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "promptinel",
	Short: "Promptinel is a deterministic security scanner for machine-interpreted natural language.",
	Long: `Promptinel is a deterministic security scanner for machine-interpreted natural language.
It statically analyzes prompts before an LLM or agent executes them and detects instructions that could cause
unintended external actions, such as data exfiltration, tool misuse, or environment manipulation.

Promptinel treats prompts as executable artifacts.`,
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("root command failed", runRoot(cmd, args))
	},
}

func runRoot(cmd *cobra.Command, _ []string) error {
	options, err := parseRootOptions(cmd)
	if err != nil {
		return err
	}

	if options.showVersion {
		fmt.Println(displayVersion())
	}

	return nil
}

func parseRootOptions(cmd *cobra.Command) (rootOptions, error) {
	showVersion, err := cmd.Flags().GetBool("version")
	if err != nil {
		return rootOptions{}, fmt.Errorf("read version flag: %w", err)
	}
	return rootOptions{showVersion: showVersion}, nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	util.ExitOnCommandError("command execution failed", rootCmd.Execute())
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print the current Promptinel version")
}

func displayVersion() string {
	return internalversion.Display()
}
