package helpers

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules"
)

func Test_RulesHelpers_AdvancePositionByByteOffset(t *testing.T) {
	t.Parallel()

	start := rules.Position{Line: 3, Column: 5}
	content := "ab\ncd"

	tests := []struct {
		name     string
		offset   int
		expected rules.Position
	}{
		{
			name:     "negative offset clamps to start",
			offset:   -1,
			expected: rules.Position{Line: 3, Column: 5},
		},
		{
			name:     "zero offset keeps start",
			offset:   0,
			expected: rules.Position{Line: 3, Column: 5},
		},
		{
			name:     "offset before newline advances column",
			offset:   2,
			expected: rules.Position{Line: 3, Column: 7},
		},
		{
			name:     "offset across newline advances line",
			offset:   3,
			expected: rules.Position{Line: 4, Column: 1},
		},
		{
			name:     "offset after newline advances new column",
			offset:   5,
			expected: rules.Position{Line: 4, Column: 3},
		},
		{
			name:     "offset beyond content clamps to end",
			offset:   100,
			expected: rules.Position{Line: 4, Column: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := AdvancePositionByByteOffset(start, content, tt.offset)
			if actual != tt.expected {
				t.Fatalf("expected position %v, got %v", tt.expected, actual)
			}
		})
	}
}
