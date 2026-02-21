package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [path ...]",
	Short: "Scan prompt files for unsafe instructions and policy violations",
	Long: `Scan prompt files for deterministic security findings before they are executed by an LLM or agent.

Examples:
  promptinel scan prompts/
  promptinel scan --config .promptinel.yaml prompts/
  promptinel scan --include "*.md" prompts/
  promptinel scan --exclude "*.yaml" prompts/`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("scan called")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
