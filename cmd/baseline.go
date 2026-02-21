package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// baselineCmd represents the baseline command
var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Create and update baseline files for CI adoption",
	Long: `Manage baseline snapshots of existing findings to support gradual adoption in CI.

Examples:
  promptinel baseline create
  promptinel baseline update`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("baseline called")
	},
}

func init() {
	rootCmd.AddCommand(baselineCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// baselineCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// baselineCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
