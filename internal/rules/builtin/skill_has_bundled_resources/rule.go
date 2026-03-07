package skillhasbundledresources

import (
	"fmt"
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

const (
	id          = "skill-has-bundled-resources"
	name        = "Skill Has Bundled Resources"
	summary     = "Detects skills that reference bundled local resources"
	description = "Skills can include scripts, references, or assets outside SKILL.md. Promptinel does not review those transitively, so they should be reviewed manually and excluded after acceptance if appropriate."
)

// Rule emits a low-severity advisory when a skill references bundled local resources.
type Rule struct{}

// New returns the skill-has-bundled-resources rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the skill-has-bundled-resources rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the skill-has-bundled-resources rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityLow,
	}
}

// CheckDocument detects skills that reference bundled local resources.
func (Rule) CheckDocument(ctx rules.Context, _ rules.DocumentView) []rules.Finding {
	if !ctx.HasReferencedSkillResources() {
		return nil
	}

	samples := ctx.Skill.ReferencedResources
	if len(samples) > 3 {
		samples = samples[:3]
	}

	message := "Skill references bundled resources that Promptinel does not review transitively; review them manually and exclude the skill directory or accepted resources if appropriate"
	if len(samples) > 0 {
		message = fmt.Sprintf("%s: %s", message, strings.Join(samples, ", "))
	}

	return []rules.Finding{{
		Message:  message,
		Position: ctx.Skill.ReferencePosition,
	}}
}
