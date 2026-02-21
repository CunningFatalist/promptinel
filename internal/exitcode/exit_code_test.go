package exitcode

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

func Test_Exitcode_CodeValues(t *testing.T) {
	if CodeWarn != 1 {
		t.Fatalf("expected CodeWarn to equal 1, got %d", CodeWarn)
	}
	if CodeFail != 2 {
		t.Fatalf("expected CodeFail to equal 2, got %d", CodeFail)
	}
}

func Test_Exitcode_ErrorMessage(t *testing.T) {
	err := Error{Code: CodeFail}
	if err.Error() != "exit code 2" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func Test_Exitcode_SeverityRank(t *testing.T) {
	if got := severityRank(config.SeverityHigh); got != 3 {
		t.Fatalf("expected high rank 3, got %d", got)
	}
	if got := severityRank(config.SeverityMedium); got != 2 {
		t.Fatalf("expected medium rank 2, got %d", got)
	}
	if got := severityRank(config.SeverityLow); got != 1 {
		t.Fatalf("expected low rank 1, got %d", got)
	}
}

func Test_Exitcode_SeverityAtLeast(t *testing.T) {
	if !severityAtLeast(config.SeverityHigh, config.SeverityMedium) {
		t.Fatal("expected high >= medium")
	}
	if !severityAtLeast(config.SeverityMedium, config.SeverityMedium) {
		t.Fatal("expected medium >= medium")
	}
	if severityAtLeast(config.SeverityLow, config.SeverityMedium) {
		t.Fatal("expected low < medium")
	}
}

func Test_Exitcode_MaxFindingSeverity(t *testing.T) {
	findings := []engine.FileFinding{
		{Finding: rules.Finding{Severity: config.SeverityLow}},
		{Finding: rules.Finding{Severity: config.SeverityHigh}},
		{Finding: rules.Finding{Severity: config.SeverityMedium}},
	}
	if got := maxFindingSeverity(findings); got != config.SeverityHigh {
		t.Fatalf("expected highest severity high, got %s", got)
	}
}

func Test_Exitcode_Resolve_NoFindings(t *testing.T) {
	p := config.Policy{FailOn: config.SeverityHigh, WarnOn: config.SeverityMedium}
	if got := Resolve(p, nil); got != CodePass {
		t.Fatalf("expected CodePass, got %d", got)
	}
}

func Test_Exitcode_Resolve_LowSeverityFindingsPass(t *testing.T) {
	p := config.Policy{FailOn: config.SeverityHigh, WarnOn: config.SeverityMedium}
	findings := []engine.FileFinding{{Finding: rules.Finding{Severity: config.SeverityLow}}}
	if got := Resolve(p, findings); got != CodePass {
		t.Fatalf("expected CodePass, got %d", got)
	}
}

func Test_Exitcode_Resolve_Warn(t *testing.T) {
	p := config.Policy{FailOn: config.SeverityHigh, WarnOn: config.SeverityMedium}
	findings := []engine.FileFinding{{Finding: rules.Finding{Severity: config.SeverityMedium}}}
	if got := Resolve(p, findings); got != CodeWarn {
		t.Fatalf("expected CodeWarn, got %d", got)
	}
}

func Test_Exitcode_Resolve_Fail(t *testing.T) {
	p := config.Policy{FailOn: config.SeverityHigh, WarnOn: config.SeverityMedium}
	findings := []engine.FileFinding{{Finding: rules.Finding{Severity: config.SeverityHigh}}}
	if got := Resolve(p, findings); got != CodeFail {
		t.Fatalf("expected CodeFail, got %d", got)
	}
}
