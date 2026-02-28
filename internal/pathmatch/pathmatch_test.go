package pathmatch

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func Test_Pathmatch_Match_SingleSegmentGlob(t *testing.T) {
	if Match("*.md", "docs/readme.md") {
		t.Fatal("expected *.md not to match docs/readme.md without basename fallback")
	}
}

func Test_Pathmatch_Match_DoubleStar(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name:    "recursive child",
			pattern: "docs/**",
			path:    "docs/a/b/readme.md",
			want:    true,
		},
		{
			name:    "immediate child",
			pattern: "docs/**",
			path:    "docs/readme.md",
			want:    true,
		},
		{
			name:    "sibling directory",
			pattern: "docs/**",
			path:    "prompts/readme.md",
			want:    false,
		},
		{
			name:    "middle recursive segment",
			pattern: "docs/**/readme.md",
			path:    "docs/a/b/readme.md",
			want:    true,
		},
		{
			name:    "empty recursive segment",
			pattern: "docs/**/readme.md",
			path:    "docs/readme.md",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.pattern, tt.path)
			if got != tt.want {
				t.Fatalf("expected %v, got %v for pattern=%q path=%q", tt.want, got, tt.pattern, tt.path)
			}
		})
	}
}

func Test_Pathmatch_Match_DoubleStar_ConsecutiveSegments(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name:    "consecutive wildcards match deep path",
			pattern: "docs/**/**/readme.md",
			path:    "docs/a/b/c/readme.md",
			want:    true,
		},
		{
			name:    "consecutive wildcards still require trailing segment",
			pattern: "docs/**/**/readme.md",
			path:    "docs/a/b/c/notes.md",
			want:    false,
		},
		{
			name:    "wildcards can match zero segments",
			pattern: "docs/**/**/readme.md",
			path:    "docs/readme.md",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.pattern, tt.path)
			if got != tt.want {
				t.Fatalf("expected %v, got %v for pattern=%q path=%q", tt.want, got, tt.pattern, tt.path)
			}
		})
	}
}

func Test_Pathmatch_Match_DoubleStar_AdversarialPatternBoundedRuntime(t *testing.T) {
	pathSegments := make([]string, 60)
	for i := range pathSegments {
		pathSegments[i] = "dir" + strconv.Itoa(i)
	}
	path := strings.Join(pathSegments, "/")

	patternParts := make([]string, 0, 121)
	for i := 0; i < 60; i++ {
		patternParts = append(patternParts, "**", "x")
	}
	pattern := strings.Join(patternParts, "/")

	start := time.Now()
	matched := Match(pattern, path)
	elapsed := time.Since(start)
	if matched {
		t.Fatalf("expected no match for adversarial pattern=%q path=%q", pattern, path)
	}
	if elapsed > time.Second {
		t.Fatalf("matcher took too long: %s", elapsed)
	}
}

func Benchmark_Pathmatch_Match_DoubleStar_Adversarial(b *testing.B) {
	pathSegments := make([]string, 80)
	for i := range pathSegments {
		pathSegments[i] = "dir" + strconv.Itoa(i)
	}
	path := strings.Join(pathSegments, "/")

	patternParts := make([]string, 0, 161)
	for i := 0; i < 80; i++ {
		patternParts = append(patternParts, "**", "x")
	}
	pattern := strings.Join(patternParts, "/")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Match(pattern, path)
	}
}
