package skillhasbundledresources

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SkillHasBundledResources_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, id, meta.ID)
	assert.Equal(t, config.SeverityLow, meta.DefaultSeverity)
}

func Test_SkillHasBundledResources_CheckDocument_DetectsReferencedResources(t *testing.T) {
	findings := evaluateRuleWithContext(t, rules.Context{
		Path: "skills/demo/SKILL.md",
		Skill: &rules.SkillContext{
			ReferencedResources: []string{
				"assets/template.txt",
				"references/api.md",
				"scripts/run.py",
				"scripts/unused.py",
			},
			ReferencePosition: rules.Position{Line: 4, Column: 8},
		},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, rules.Position{Line: 4, Column: 8}, findings[0].Position)
	assert.Contains(t, findings[0].Message, "review them manually")
	assert.Contains(t, findings[0].Message, "assets/template.txt")
	assert.Contains(t, findings[0].Message, "references/api.md")
	assert.Contains(t, findings[0].Message, "scripts/run.py")
	assert.NotContains(t, findings[0].Message, "scripts/unused.py")
}

func Test_SkillHasBundledResources_CheckDocument_IgnoresWhenNoResolvedResources(t *testing.T) {
	findings := evaluateRuleWithContext(t, rules.Context{
		Path:  "skills/demo/SKILL.md",
		Skill: &rules.SkillContext{},
	})
	assert.Empty(t, findings)
}

func evaluateRuleWithContext(t *testing.T, ctx rules.Context) []rules.Finding {
	t.Helper()

	registry := rules.NewRegistry()
	err := registry.Register(New())
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	return rules.Evaluate(compiled, ctx, "placeholder")
}
