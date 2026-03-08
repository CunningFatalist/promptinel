package engine

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func Test_Engine_NormalizeSkillReference_NormalizesSupportedPaths(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		expectOK bool
	}{
		{
			name:     "strips query and fragment",
			input:    " ./scripts/run.py?raw=1#section ",
			expected: "scripts/run.py",
			expectOK: true,
		},
		{
			name:     "cleans nested relative path",
			input:    "references/../scripts/run.py",
			expected: "scripts/run.py",
			expectOK: true,
		},
		{
			name:     "keeps asset path",
			input:    "assets/icon.svg",
			expected: "assets/icon.svg",
			expectOK: true,
		},
		{
			name:     "rejects external url",
			input:    "https://example.com/scripts/run.py",
			expectOK: false,
		},
		{
			name:     "rejects anchor",
			input:    "#resources",
			expectOK: false,
		},
		{
			name:     "rejects parent traversal",
			input:    "../scripts/run.py",
			expectOK: false,
		},
		{
			name:     "rejects absolute path",
			input:    "/tmp/scripts/run.py",
			expectOK: false,
		},
		{
			name:     "rejects bare resource directory",
			input:    "scripts",
			expectOK: false,
		},
		{
			name:     "rejects unrelated path",
			input:    "notes/run.py",
			expectOK: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, ok := normalizeSkillReference(testCase.input)
			if ok != testCase.expectOK {
				t.Fatalf("unexpected ok value: got %v want %v", ok, testCase.expectOK)
			}
			if actual != testCase.expected {
				t.Fatalf("unexpected normalized path: got %q want %q", actual, testCase.expected)
			}
		})
	}
}

func Test_Engine_CollectSkillResourceReferences_FindsMarkdownLinksAndBarePaths(t *testing.T) {
	content := `Use [runner](scripts/run.py), [guide](references/guide.md), and bare scripts/local.sh.
Also review [icon](assets/icon.svg) and ignore [external](https://example.com/demo).`

	references := collectSkillResourceReferences(content)
	paths := make([]string, 0, len(references))
	for _, reference := range references {
		paths = append(paths, reference.path)
	}
	slices.Sort(paths)

	expected := []string{
		"assets/icon.svg",
		"https://example.com/demo",
		"references/guide.md",
		"scripts/run.py",
	}
	if !slices.Equal(paths, expected) {
		t.Fatalf("unexpected collected paths: got %#v want %#v", paths, expected)
	}
}

func Test_Engine_DeriveSkillContext_DeduplicatesSortsAndTracksFirstReference(t *testing.T) {
	root := t.TempDir()
	skillDir := filepath.Join(root, "skills", "demo")
	if err := os.MkdirAll(filepath.Join(skillDir, "scripts"), 0o755); err != nil {
		t.Fatalf("create scripts directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(skillDir, "references"), 0o755); err != nil {
		t.Fatalf("create references directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(skillDir, "assets"), 0o755); err != nil {
		t.Fatalf("create assets directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "scripts", "run.py"), []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatalf("write script file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "references", "guide.md"), []byte("# Guide\n"), 0o644); err != nil {
		t.Fatalf("write reference file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "assets", "icon.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatalf("write asset file: %v", err)
	}

	content := `Use [icon](assets/icon.svg) first.
Then call [runner](./scripts/run.py?raw=1).
Repeat scripts/run.py later.
See [guide](references/guide.md#intro).
Ignore [external](https://example.com/demo) and ../scripts/missing.py.
`

	context := deriveSkillContext(filepath.Join(skillDir, "SKILL.md"), content)
	if context == nil {
		t.Fatal("expected skill context")
	}

	expectedResources := []string{
		"assets/icon.svg",
		"references/guide.md",
		"scripts/run.py",
	}
	if !slices.Equal(context.ReferencedResources, expectedResources) {
		t.Fatalf("unexpected referenced resources: got %#v want %#v", context.ReferencedResources, expectedResources)
	}
	if context.ReferencePosition.Line != 1 || context.ReferencePosition.Column != 12 {
		t.Fatalf("unexpected first reference position: %#v", context.ReferencePosition)
	}
}

func Test_Engine_DeriveSkillContext_ReturnsNilForNonSkillFiles(t *testing.T) {
	context := deriveSkillContext("/tmp/demo.md", "Use scripts/run.py.")
	if context != nil {
		t.Fatalf("expected nil context for non-skill file, got %#v", context)
	}
}
