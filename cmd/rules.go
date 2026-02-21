package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rulesCmd represents the rules command
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List and explain Promptinel detection rules",
	Long: `Inspect the built-in Promptinel rule set and get details for a specific rule.

Examples:
  promptinel rules list
  promptinel rules describe no-shell-commands`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("rules called")
	},
}

func init() {
	rootCmd.AddCommand(rulesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// rulesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// rulesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
