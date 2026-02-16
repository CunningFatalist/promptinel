package cmd

import (
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/spf13/cobra"
)

// Version is the current version of the application, set at build time.
var Version = "development"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "promptinel",
	Short: "Promptinel is a security-focused static analysis tool for LLM prompts.",
	Long: `Promptinel is a security-focused static analysis tool for LLM prompts. 
It detects prompt injection, hidden Unicode messages, malicious 
instructions, and unsafe template usage.`,
	Run: func(cmd *cobra.Command, args []string) {
		versionFlag, err := cmd.Flags().GetBool("version")
		util.ExitOnError("error reading version flag", err)

		if versionFlag && Version == "development" {
			fmt.Println(Version)
		} else if versionFlag {
			fmt.Printf("v%s\n", Version)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print the current Promptinel version")
}
