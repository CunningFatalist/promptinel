package rulecatalog

import "testing"

func Test_RuleCatalog_List_ReturnsSortedRules(t *testing.T) {
	ruleSet, err := List()
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
	_, exists, err := Describe("unknown-rule")
	if err != nil {
		t.Fatalf("describe rule: %v", err)
	}
	if exists {
		t.Fatal("expected unknown rule to not exist")
	}
}
