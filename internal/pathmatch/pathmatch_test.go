package pathmatch

import "testing"

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
