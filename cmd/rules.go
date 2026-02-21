package cmd

import (
	"fmt"
	"sort"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// rulesCmd represents the rules command.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List and explain Promptinel detection rules",
	Long: `Inspect the built-in Promptinel rule set and get details for a specific rule.

Examples:
  promptinel rules list
  promptinel rules describe no-unsafe-templates`,
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available built-in rules",
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("rules list command failed", runRulesList())
	},
}

var rulesDescribeCmd = &cobra.Command{
	Use:   "describe [rule-id]",
	Short: "Describe a single built-in rule",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.ExitOnCommandError("rules describe command failed", runRulesDescribe(args))
	},
}

func runRulesList() error {
	registry, err := builtin.NewRegistry()
	if err != nil {
		return fmt.Errorf("initialize rule registry: %w", err)
	}

	ruleSet := registry.List()
	sort.SliceStable(ruleSet, func(i, j int) bool {
		return ruleSet[i].ID < ruleSet[j].ID
	})
	maxSeverityWidth := maxSeverityLabelWidth(ruleSet)
	for _, meta := range ruleSet {
		severityLabel := util.PadRight(meta.DefaultSeverity.String(), maxSeverityWidth)
		fmt.Printf("[ %s ] %s %s\n", addColorToSeverityLabel(meta.DefaultSeverity, severityLabel), addColorToID(meta.ID), meta.Summary)
	}
	return nil
}

func maxSeverityLabelWidth(ruleSet []rules.Metadata) int {
	maxWidth := 0
	for _, rule := range ruleSet {
		if len(rule.DefaultSeverity.String()) > maxWidth {
			maxWidth = len(rule.DefaultSeverity.String())
		}
	}
	return maxWidth
}

func runRulesDescribe(args []string) error {
	registry, err := builtin.NewRegistry()
	if err != nil {
		return fmt.Errorf("initialize rule registry: %w", err)
	}

	id := args[0]
	meta, exists := registry.Describe(id)
	if !exists {
		return fmt.Errorf("unknown rule %q", id)
	}

	fmt.Printf("[ %s ] %s\n", addColorToLabel("id              "), meta.ID)
	fmt.Printf("[ %s ] %s\n", addColorToLabel("name            "), meta.Name)
	fmt.Printf("[ %s ] %s\n", addColorToLabel("default severity"), meta.DefaultSeverity)
	fmt.Printf("[ %s ] %s\n", addColorToLabel("summary         "), meta.Summary)
	fmt.Printf("[ %s ] %s\n", addColorToLabel("description     "), meta.Description)

	return nil
}

func addColorToLabel(label string) string {
	return color.BlueString(label)
}

func addColorToID(id string) string {
	return color.CyanString(id)
}

func addColorToSeverityLabel(severity config.Severity, severityLabel string) string {
	switch severity {
	case config.SeverityHigh:
		return color.RedString(severityLabel)
	case config.SeverityMedium:
		return color.YellowString(severityLabel)
	case config.SeverityLow:
		return color.BlueString(severityLabel)
	}

	return severityLabel
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesDescribeCmd)
	rootCmd.AddCommand(rulesCmd)
}
