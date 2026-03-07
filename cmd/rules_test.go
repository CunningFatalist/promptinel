package cmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/ruledocs"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
	"github.com/CunningFatalist/promptinel/internal/util"
	"github.com/fatih/color"
)

func Test_Cmd_RulesListCommand_OutputIsSorted(t *testing.T) {
	previousNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = previousNoColor
	})

	output := captureStdout(t, func() {
		if err := runRulesListWithOptions(rulesListOptions{}); err != nil {
			t.Fatalf("run rules list: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	registry, err := builtin.NewRegistry()
	if err != nil {
		t.Fatalf("initialize builtin rule registry: %v", err)
	}

	expectedRuleCount := len(registry.List())
	if len(lines) != expectedRuleCount {
		t.Fatalf("expected %d rules, got %d (%q)", expectedRuleCount, len(lines), output)
	}
	if !strings.Contains(lines[0], " no-bidi-control-characters ") {
		t.Fatalf("expected first rule to be no-bidi-control-characters, got %q", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], " skill-has-bundled-resources ") {
		t.Fatalf("expected last rule to be skill-has-bundled-resources, got %q", lines[len(lines)-1])
	}

	pattern := regexp.MustCompile(`^\[ ([^]]+) \] `)
	maxSeverityWordLength := 0
	severityLabels := make([]string, 0, len(lines))
	for _, line := range lines {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) != 2 {
			t.Fatalf("expected bracketed severity label, got %q", line)
		}
		severityLabel := matches[1]
		severityLabels = append(severityLabels, severityLabel)

		severityWordLength := len(strings.TrimSpace(severityLabel))
		if severityWordLength > maxSeverityWordLength {
			maxSeverityWordLength = severityWordLength
		}
	}
	for _, severityLabel := range severityLabels {
		if len(severityLabel) != maxSeverityWordLength {
			t.Fatalf("expected severity label %q to be padded to width %d", severityLabel, maxSeverityWordLength)
		}
	}
}

func Test_Cmd_RulesListCommand_WithDescription_PrintsSecondAlignedLine(t *testing.T) {
	previousNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = previousNoColor
	})

	output := captureStdout(t, func() {
		if err := runRulesListWithOptions(rulesListOptions{
			ShowDescription: true,
		}); err != nil {
			t.Fatalf("run rules list with description: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	registry, err := builtin.NewRegistry()
	if err != nil {
		t.Fatalf("initialize builtin rule registry: %v", err)
	}

	expectedRuleCount := len(registry.List())
	if len(lines) != expectedRuleCount*2 {
		t.Fatalf("expected %d lines, got %d (%q)", expectedRuleCount*2, len(lines), output)
	}

	headerPattern := regexp.MustCompile(`^\[ ([^]]+) \] [^ ]+ `)
	for idx := 0; idx < len(lines); idx += 2 {
		headerLine := lines[idx]
		descriptionLine := lines[idx+1]
		matches := headerPattern.FindStringSubmatch(headerLine)
		if len(matches) != 2 {
			t.Fatalf("expected bracketed severity line, got %q", headerLine)
		}

		indent := len("[ " + matches[1] + " ] ")
		if len(descriptionLine) <= indent {
			t.Fatalf("expected description line to contain indentation and text, got %q", descriptionLine)
		}
		if descriptionLine[:indent] != strings.Repeat(" ", indent) {
			t.Fatalf("expected description line %q to be indented by %d spaces", descriptionLine, indent)
		}
	}
}

func Test_Cmd_RulesListCommand_WithDescriptionFlag_PrintsDescriptions(t *testing.T) {
	previousNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = previousNoColor
		rootCmd.SetArgs(nil)
		_ = rulesListCmd.Flags().Set("description", "false")
	})

	rootCmd.SetArgs([]string{"rules", "list", "--description"})

	output := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute rules list --description: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	registry, err := builtin.NewRegistry()
	if err != nil {
		t.Fatalf("initialize builtin rule registry: %v", err)
	}

	expectedRuleCount := len(registry.List())
	if len(lines) != expectedRuleCount*2 {
		t.Fatalf("expected %d lines, got %d (%q)", expectedRuleCount*2, len(lines), output)
	}
}

func Test_Cmd_RulesListCommand_WithDocs_PrintsDocumentationURLs(t *testing.T) {
	previousNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = previousNoColor
	})

	output := captureStdout(t, func() {
		if err := runRulesListWithOptions(rulesListOptions{
			ShowDocs: true,
		}); err != nil {
			t.Fatalf("run rules list with docs: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	registry, err := builtin.NewRegistry()
	if err != nil {
		t.Fatalf("initialize builtin rule registry: %v", err)
	}

	expectedRuleCount := len(registry.List())
	if len(lines) != expectedRuleCount*2 {
		t.Fatalf("expected %d lines, got %d (%q)", expectedRuleCount*2, len(lines), output)
	}
	if !strings.Contains(output, ruledocs.URL("NoBidiControlCharacters.md")) {
		t.Fatalf("expected docs URL in output, got %q", output)
	}
}

func Test_Cmd_RulesDescribeCommand_DescribesKnownRule(t *testing.T) {
	previousNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = previousNoColor
	})

	output := captureStdout(t, func() {
		if err := runRulesDescribe(nil, []string{"no-zero-width"}); err != nil {
			t.Fatalf("run rules describe: %v", err)
		}
	})

	if !regexp.MustCompile(`\[ id +\] no-zero-width`).MatchString(output) {
		t.Fatalf("expected described rule id in output, got %q", output)
	}
	if !regexp.MustCompile(`\[ name +\] No Zero Width Characters`).MatchString(output) {
		t.Fatalf("expected described rule name in output, got %q", output)
	}
	if !regexp.MustCompile(regexp.QuoteMeta("[ docs             ] " + ruledocs.URL("NoZeroWidth.md"))).MatchString(output) {
		t.Fatalf("expected described rule docs URL in output, got %q", output)
	}
}

func Test_Cmd_RulesDescribeCommand_ReturnsErrorForUnknownRule(t *testing.T) {
	err := runRulesDescribe(nil, []string{"unknown-rule"})
	if err == nil {
		t.Fatal("expected error for unknown rule")
	}
	if !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("expected unknown rule error, got %v", err)
	}
}

func Test_Cmd_MaxSeverityLabelWidth_UsesLongestSeverity(t *testing.T) {
	ruleSet := []rules.Metadata{
		{DefaultSeverity: config.SeverityMedium},
		{DefaultSeverity: config.SeverityHigh},
		{DefaultSeverity: config.SeverityLow},
	}

	width := maxSeverityLabelWidth(ruleSet)
	medium := config.SeverityMedium
	if width != len(medium.String()) {
		t.Fatalf("expected width %d, got %d", len(medium.String()), width)
	}

	highSeverity := config.SeverityHigh
	lowSeverity := config.SeverityLow
	high := util.PadRight(highSeverity.String(), width)
	low := util.PadRight(lowSeverity.String(), width)
	if high != "high  " {
		t.Fatalf("expected padded high severity label, got %q", high)
	}
	if low != "low   " {
		t.Fatalf("expected padded low severity label, got %q", low)
	}
}
