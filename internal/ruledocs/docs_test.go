package ruledocs

import "testing"

func Test_RuleDocs_Path(t *testing.T) {
	t.Parallel()

	if got := Path("NoZeroWidth.md"); got != "docs/rules/NoZeroWidth.md" {
		t.Fatalf("expected docs path, got %q", got)
	}
	if got := Path(""); got != "" {
		t.Fatalf("expected empty docs path, got %q", got)
	}
}

func Test_RuleDocs_URL(t *testing.T) {
	t.Parallel()

	if got := URL("NoZeroWidth.md"); got != "https://github.com/CunningFatalist/promptinel/blob/main/docs/rules/NoZeroWidth.md" {
		t.Fatalf("expected docs URL, got %q", got)
	}
	if got := URL(""); got != "" {
		t.Fatalf("expected empty docs URL, got %q", got)
	}
}
