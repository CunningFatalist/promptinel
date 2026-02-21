package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// sanitizeCmd represents the sanitize command
var sanitizeCmd = &cobra.Command{
	Use:   "sanitize [path ...]",
	Short: "Sanitize prompt files with safe, deterministic transformations",
	Long: `Sanitize prompt files using only safe transformations, such as removing invisible characters.

Examples:
  promptinel sanitize prompts/
  promptinel sanitize --apply prompts/
  promptinel sanitize --config .promptinel.yaml --apply prompts/
  promptinel sanitize --include "*.md" --apply prompts/
  promptinel sanitize --exclude "*.yaml" --apply prompts/`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("sanitize called")
	},
}

func init() {
	rootCmd.AddCommand(sanitizeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sanitizeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sanitizeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
