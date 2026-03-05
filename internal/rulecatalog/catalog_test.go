package rulecatalog

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
)

func Test_RuleCatalog_List_ReturnsSortedRules(t *testing.T) {
	ruleSet, err := List(builtin.NewRegistry)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(ruleSet) < 2 {
		t.Fatalf("expected at least two rules, got %d", len(ruleSet))
	}
	for i := 1; i < len(ruleSet); i++ {
		if ruleSet[i-1].ID > ruleSet[i].ID {
			t.Fatalf("rule list not sorted: %s before %s", ruleSet[i-1].ID, ruleSet[i].ID)
		}
	}
}

func Test_RuleCatalog_Describe_UnknownRule(t *testing.T) {
	_, exists, err := Describe(builtin.NewRegistry, "unknown-rule")
	if err != nil {
		t.Fatalf("describe rule: %v", err)
	}
	if exists {
		t.Fatal("expected unknown rule to not exist")
	}
}

func Test_RuleCatalog_List_ReturnsErrorWhenRegistryFactoryMissing(t *testing.T) {
	_, err := List(nil)
	if err == nil {
		t.Fatal("expected missing registry factory error")
	}
}

func Test_RuleCatalog_Describe_ReturnsErrorWhenRegistryFactoryMissing(t *testing.T) {
	_, _, err := Describe(nil, "no-zero-width")
	if err == nil {
		t.Fatal("expected missing registry factory error")
	}
}
