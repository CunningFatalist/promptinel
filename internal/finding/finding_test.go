package finding

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/rules"
)

func Test_Finding_IsOversizedFileSkip(t *testing.T) {
	if !IsOversizedFileSkip(FileFinding{Finding: rules.Finding{ID: OversizedFileSkipID}}) {
		t.Fatal("expected oversized skip finding to match")
	}
	if IsOversizedFileSkip(FileFinding{Finding: rules.Finding{ID: UnreadableFileSkipID}}) {
		t.Fatal("expected unreadable skip finding not to match oversized skip")
	}
}

func Test_Finding_IsUnreadableFileSkip(t *testing.T) {
	if !IsUnreadableFileSkip(FileFinding{Finding: rules.Finding{ID: UnreadableFileSkipID}}) {
		t.Fatal("expected unreadable skip finding to match")
	}
	if IsUnreadableFileSkip(FileFinding{Finding: rules.Finding{ID: OversizedFileSkipID}}) {
		t.Fatal("expected oversized skip finding not to match unreadable skip")
	}
}
