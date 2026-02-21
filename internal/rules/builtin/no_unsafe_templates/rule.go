package nounsafetemplates

import (
	"regexp"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "no-unsafe-templates"
	name        = "No Unsafe Templates"
	summary     = "Detects risky template expressions with execution or exfiltration intent"
	description = "Template expressions that invoke command, environment, or network-related operations increase prompt execution risk."
)

// Rule detects unsafe signals in template segments.
type Rule struct{}

// New returns the no-unsafe-templates rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-unsafe-templates rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

var unsafeTemplateSignalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bexec(?:ute)?\s*\(`),
	regexp.MustCompile(`\bsystem\s*\(`),
	regexp.MustCompile(`\b(?:bash|sh|zsh|pwsh|powershell)\b`),
	regexp.MustCompile(`\bcmd(?:\.exe)?\b`),
	regexp.MustCompile(`\bprocess\.env\b`),
	regexp.MustCompile(`\bos\.[a-z_]+\s*\(`),
	regexp.MustCompile(`\bgetenv\s*\(`),
	regexp.MustCompile(`\breadfile\s*\(`),
	regexp.MustCompile(`\bopen\s*\(`),
	regexp.MustCompile(`https?://`),
	regexp.MustCompile(`\b(?:curl|wget)\b`),
}

// Metadata returns public metadata for the no-unsafe-templates rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityMedium,
	}
}

// CheckSegment scans template segments for unsafe execution signals.
func (Rule) CheckSegment(_ rules.Context, segment rules.Segment) []rules.Finding {
	if segment.Type != rules.SegmentTypeTemplate {
		return nil
	}

	expression := strings.ToLower(segment.Content)
	if !containsUnsafeSignal(expression) {
		return nil
	}

	return []rules.Finding{{
		Message:  "Unsafe template expression detected",
		Position: segment.Position,
	}}
}

func containsUnsafeSignal(expression string) bool {
	for _, pattern := range unsafeTemplateSignalPatterns {
		if pattern.MatchString(expression) {
			return true
		}
	}
	return false
}
