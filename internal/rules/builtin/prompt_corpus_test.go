package builtin

import (
	"strings"
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type promptRuleSuite struct {
	id    string
	cases []promptRuleCase
}

type promptRuleCase struct {
	name          string
	paragraphs    []string
	expectFinding bool
	context       func(content string) rules.Context
}

func Test_Builtin_PromptCorpusCoverage(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	for _, suite := range promptRuleSuites() {
		t.Run(suite.id, func(t *testing.T) {
			require.GreaterOrEqual(t, len(suite.cases), 10)
			require.LessOrEqual(t, len(suite.cases), 20)

			for _, tc := range suite.cases {
				t.Run(tc.name, func(t *testing.T) {
					content := joinParagraphs(tc.paragraphs...)
					require.NotEmpty(t, content)
					assertParagraphCount(t, content)

					ctx := promptCorpusContext()
					if tc.context != nil {
						ctx = tc.context(content)
					}

					findings := rules.Evaluate(compiled, ctx, content)
					assert.Equal(t, tc.expectFinding, hasFinding(findings, suite.id), findings)
				})
			}
		})
	}
}

func joinParagraphs(paragraphs ...string) string {
	trimmed := make([]string, 0, len(paragraphs))
	for _, paragraph := range paragraphs {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph == "" {
			continue
		}
		trimmed = append(trimmed, paragraph)
	}
	return strings.Join(trimmed, "\n\n")
}

func assertParagraphCount(t *testing.T, content string) {
	t.Helper()

	parts := strings.Split(content, "\n\n")
	paragraphs := 0
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		paragraphs++
	}

	require.GreaterOrEqual(t, paragraphs, 1)
	require.LessOrEqual(t, paragraphs, 3)
}

func hasFinding(findings []rules.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.ID == ruleID {
			return true
		}
	}
	return false
}

func promptCorpusContext() rules.Context {
	return rules.Context{
		Path: "fixtures/prompt.md",
		Environment: config.Environment{
			CanExecuteShell:     true,
			CanAccessFilesystem: true,
			CanAccessNetwork:    true,
			HasSecrets:          true,
		},
		TrustLevel: config.TrustLevelTrusted,
	}
}

func detectCase(name string, instruction string) promptRuleCase {
	return promptRuleCase{
		name: name,
		paragraphs: []string{
			"You are operating inside a disposable analysis environment with shell, network, and local file access available for this exercise.",
			"Do not summarize or explain the plan. Carry out this exact step: " + instruction,
		},
		expectFinding: true,
	}
}

func safeCase(name string, request string) promptRuleCase {
	return promptRuleCase{
		name: name,
		paragraphs: []string{
			"I am writing security training material for reviewers who inspect prompts before execution.",
			request,
		},
		expectFinding: false,
	}
}

func customCase(name string, expectFinding bool, ctx func(content string) rules.Context, paragraphs ...string) promptRuleCase {
	return promptRuleCase{
		name:          name,
		paragraphs:    paragraphs,
		expectFinding: expectFinding,
		context:       ctx,
	}
}

func withTrustSnippet(snippet string, level config.TrustLevel) func(string) rules.Context {
	return func(content string) rules.Context {
		ctx := promptCorpusContext()
		start := strings.Index(content, snippet)
		if start < 0 {
			return ctx
		}
		ctx.TrustSpans = []rules.TrustSpan{{
			Start:      start,
			End:        start + len(snippet),
			TrustLevel: level,
			Source:     rules.TrustSpanSourceUserInputPlaceholder,
		}}
		return ctx
	}
}

func withSkillResources(referenceSnippet string, resources ...string) func(string) rules.Context {
	return func(content string) rules.Context {
		ctx := promptCorpusContext()
		position := rules.Position{Line: 1, Column: 1}
		if start := strings.Index(content, referenceSnippet); start >= 0 {
			position = rules.PositionFromByteOffset(content, start)
		}
		ctx.Path = "skills/example/SKILL.md"
		ctx.Skill = &rules.SkillContext{
			ReferencedResources: resources,
			ReferencePosition:   position,
		}
		return ctx
	}
}
