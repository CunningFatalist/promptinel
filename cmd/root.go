package cmd

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

const DevelopmentVersion = "development"

// Version is the current version of the application, set at build time.
var Version = DevelopmentVersion

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "promptinel",
	Short: "Promptinel is a deterministic security scanner for machine-interpreted natural language.",
	Long: `Promptinel is a deterministic security scanner for machine-interpreted natural language. 
It statically analyzes prompts before an LLM or agent executes them and detects instructions that could cause
unintended external actions, such as data exfiltration, tool misuse, or environment manipulation.

Promptinel treats prompts as executable artifacts.`,
	Run: func(cmd *cobra.Command, args []string) {
		versionFlag, err := cmd.Flags().GetBool("version")
		util.ExitOnError("error reading version flag", err)

		if versionFlag {
			fmt.Println(displayVersion())
		}
	},
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
	version := effectiveVersion()
	if version == DevelopmentVersion {
		return version
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func effectiveVersion() string {
	if Version != DevelopmentVersion {
		return Version
	}
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return DevelopmentVersion
	}
	if buildInfo.Main.Version == "" || buildInfo.Main.Version == "(devel)" {
		return DevelopmentVersion
	}
	return buildInfo.Main.Version
}
