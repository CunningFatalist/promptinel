package filters

import (
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
)

func Test_Filters_ValidateGlobPatterns_InvalidPattern(t *testing.T) {
	err := ValidateGlobPatterns("include", []string{"invalid["})
	if err == nil {
		t.Fatal("expected glob validation error")
	}
	if !strings.Contains(err.Error(), "invalid include pattern") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_Filters_ResolveEffective_UsesConfigByDefault(t *testing.T) {
	cfg := &config.Config{Filters: config.Filters{Include: []string{"*.md"}, Exclude: []string{"*.yaml"}}}

	includes, excludes := ResolveEffective(cfg, nil, nil, false, false)

	if len(includes) != 1 || includes[0] != "*.md" {
		t.Fatalf("unexpected includes: %#v", includes)
	}
	if len(excludes) != 1 || excludes[0] != "*.yaml" {
		t.Fatalf("unexpected excludes: %#v", excludes)
	}
}

func Test_Filters_ResolveEffective_CLIOverride(t *testing.T) {
	cfg := &config.Config{Filters: config.Filters{Include: []string{"*.md"}, Exclude: []string{"*.yaml"}}}

	includes, excludes := ResolveEffective(cfg, []string{"*.txt"}, []string{"*.tmp"}, true, true)

	if len(includes) != 1 || includes[0] != "*.txt" {
		t.Fatalf("unexpected includes: %#v", includes)
	}
	if len(excludes) != 1 || excludes[0] != "*.tmp" {
		t.Fatalf("unexpected excludes: %#v", excludes)
	}
}

func Test_Filters_ResolveEffective_CLICanClearConfigFilters(t *testing.T) {
	cfg := &config.Config{Filters: config.Filters{Include: []string{"*.md"}, Exclude: []string{"*.yaml"}}}

	includes, excludes := ResolveEffective(cfg, []string{}, []string{}, true, true)

	if len(includes) != 0 {
		t.Fatalf("expected empty includes, got %#v", includes)
	}
	if len(excludes) != 0 {
		t.Fatalf("expected empty excludes, got %#v", excludes)
	}
}

func Test_Filters_Match_AppliesIncludeThenExclude(t *testing.T) {
	if !Match("docs/prompt.md", []string{"*.md"}, nil) {
		t.Fatal("expected include match")
	}
	if Match("docs/prompt.txt", []string{"*.md"}, nil) {
		t.Fatal("expected include mismatch")
	}
	if Match("docs/prompt.md", []string{"*.md"}, []string{"docs/**"}) {
		t.Fatal("expected exclude to win")
	}
}
