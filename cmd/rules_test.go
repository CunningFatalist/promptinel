package cmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
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
		if err := runRulesList(); err != nil {
			t.Fatalf("run rules list: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 18 {
		t.Fatalf("expected 18 rules, got %d (%q)", len(lines), output)
	}
	if !strings.Contains(lines[0], " no-bidi-control-characters ") {
		t.Fatalf("expected first rule to be no-bidi-control-characters, got %q", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], " no-zero-width ") {
		t.Fatalf("expected last rule to be no-zero-width, got %q", lines[len(lines)-1])
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

func Test_Cmd_RulesDescribeCommand_DescribesKnownRule(t *testing.T) {
	previousNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = previousNoColor
	})

	output := captureStdout(t, func() {
		if err := runRulesDescribe([]string{"no-zero-width"}); err != nil {
			t.Fatalf("run rules describe: %v", err)
		}
	})

	if !regexp.MustCompile(`\[ id +\] no-zero-width`).MatchString(output) {
		t.Fatalf("expected described rule id in output, got %q", output)
	}
	if !regexp.MustCompile(`\[ name +\] No Zero Width Characters`).MatchString(output) {
		t.Fatalf("expected described rule name in output, got %q", output)
	}
}

func Test_Cmd_RulesDescribeCommand_ReturnsErrorForUnknownRule(t *testing.T) {
	err := runRulesDescribe([]string{"unknown-rule"})
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
