package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func Test_Cmd_SanitizeWithOptions_DryRunPrintsPlannedChanges(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	content := "line1\r\nline2\u200b\r\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	output := captureStdout(t, func() {
		runErr := runSanitizeWithOptions([]string{"."}, sanitizeOptions{
			includes: []string{"*.md"},
		})
		if runErr != nil {
			t.Fatalf("run sanitize: %v", runErr)
		}
	})

	if !strings.Contains(output, "would sanitize") {
		t.Fatalf("expected dry-run output, got %q", output)
	}

	persisted, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read fixture after dry-run: %v", err)
	}
	if string(persisted) != content {
		t.Fatalf("expected dry-run to keep original content, got %q", string(persisted))
	}
}

func Test_Cmd_SanitizeWithOptions_ApplyWritesChanges(t *testing.T) {
	workingDir := t.TempDir()
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\nline2\u200b\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	if err := runSanitizeWithOptions([]string{"."}, sanitizeOptions{
		includes: []string{"*.md"},
		apply:    true,
	}); err != nil {
		t.Fatalf("run sanitize --apply: %v", err)
	}

	persisted, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read fixture after apply: %v", err)
	}

	if string(persisted) != "line1\nline2\n" {
		t.Fatalf("unexpected sanitized content: %q", string(persisted))
	}
}

func Test_Cmd_SanitizeOptionsFromCommand_ReadsFlags(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("config", "", "")
	command.Flags().Bool("no-config-discovery", false, "")
	command.Flags().StringArray("include", nil, "")
	command.Flags().StringArray("exclude", nil, "")
	command.Flags().Bool("apply", false, "")

	if err := command.Flags().Set("config", "custom.yaml"); err != nil {
		t.Fatalf("set config flag: %v", err)
	}
	if err := command.Flags().Set("include", "*.md"); err != nil {
		t.Fatalf("set include flag: %v", err)
	}
	if err := command.Flags().Set("exclude", "*.txt"); err != nil {
		t.Fatalf("set exclude flag: %v", err)
	}
	if err := command.Flags().Set("apply", "true"); err != nil {
		t.Fatalf("set apply flag: %v", err)
	}
	if err := command.Flags().Set("no-config-discovery", "true"); err != nil {
		t.Fatalf("set no-config-discovery flag: %v", err)
	}

	options, err := sanitizeOptionsFromCommand(command)
	if err != nil {
		t.Fatalf("read sanitize options: %v", err)
	}

	if options.configFile != "custom.yaml" {
		t.Fatalf("expected config file custom.yaml, got %q", options.configFile)
	}
	if !options.apply {
		t.Fatal("expected apply option to be true")
	}
	if !options.noConfigDiscovery {
		t.Fatal("expected no-config-discovery option to be true")
	}
	if len(options.includes) != 1 || options.includes[0] != "*.md" {
		t.Fatalf("unexpected includes: %#v", options.includes)
	}
	if len(options.excludes) != 1 || options.excludes[0] != "*.txt" {
		t.Fatalf("unexpected excludes: %#v", options.excludes)
	}
}

func Test_Cmd_SanitizeWithOptions_ApplySkipsSymlink(t *testing.T) {
	workingDir := t.TempDir()
	target := filepath.Join(workingDir, "target.md")
	if err := os.WriteFile(target, []byte("line1\r\nline2\u200b\r\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	link := filepath.Join(workingDir, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	output := captureStdout(t, func() {
		if err := runSanitizeWithOptions([]string{link}, sanitizeOptions{apply: true}); err != nil {
			t.Fatalf("run sanitize --apply: %v", err)
		}
	})
	if !strings.Contains(output, "symbolic links are not sanitized") {
		t.Fatalf("expected symlink skip message, got %q", output)
	}

	persisted, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target file: %v", err)
	}
	if string(persisted) != "line1\r\nline2\u200b\r\n" {
		t.Fatalf("expected target file to be unchanged, got %q", string(persisted))
	}
}

func Test_Cmd_SanitizeWithOptions_NoConfigDiscovery_IgnoresLocalConfig(t *testing.T) {
	workingDir := t.TempDir()
	configPath := filepath.Join(workingDir, ".promptinel.yaml")
	configContent := `
limits:
  max_file_size_bytes: 1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	file := filepath.Join(workingDir, "prompt.md")
	if err := os.WriteFile(file, []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	previousWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read working directory: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("switch working directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWorkingDir)
	})

	withDiscovery := captureStdout(t, func() {
		if err := runSanitizeWithOptions([]string{"."}, sanitizeOptions{}); err != nil {
			t.Fatalf("run sanitize with discovery: %v", err)
		}
	})
	if !strings.Contains(withDiscovery, "exceeds limits.max_file_size_bytes=1") {
		t.Fatalf("expected discovered config to apply max size limit, got %q", withDiscovery)
	}

	withoutDiscovery := captureStdout(t, func() {
		if err := runSanitizeWithOptions([]string{"."}, sanitizeOptions{noConfigDiscovery: true}); err != nil {
			t.Fatalf("run sanitize without discovery: %v", err)
		}
	})
	if !strings.Contains(withoutDiscovery, "would sanitize") {
		t.Fatalf("expected sanitization to proceed with defaults, got %q", withoutDiscovery)
	}
}

func Test_Cmd_SanitizeWithOptions_SkipsSymlinkedDirectory(t *testing.T) {
	workingDir := t.TempDir()
	targetDir := filepath.Join(workingDir, "real")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("create target dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "prompt.md"), []byte("line1\r\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	linkDir := filepath.Join(workingDir, "linked")
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Fatalf("create dir symlink: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runSanitizeWithOptions([]string{linkDir}, sanitizeOptions{}); err != nil {
			t.Fatalf("run sanitize: %v", err)
		}
	})
	if !strings.Contains(output, "symbolic links are not sanitized") {
		t.Fatalf("expected symlink directory skip output, got %q", output)
	}
}

func Test_Cmd_WriteFileAtomically_DoesNotWriteThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is environment-dependent on windows")
	}

	workingDir := t.TempDir()
	victimPath := filepath.Join(workingDir, "victim.md")
	if err := os.WriteFile(victimPath, []byte("victim-original"), 0o644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}
	linkPath := filepath.Join(workingDir, "link.md")
	if err := os.Symlink(victimPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if err := writeFileAtomically(linkPath, []byte("replacement"), 0o644); err != nil {
		t.Fatalf("write file atomically: %v", err)
	}

	victimContent, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("read victim file: %v", err)
	}
	if string(victimContent) != "victim-original" {
		t.Fatalf("expected victim file unchanged, got %q", string(victimContent))
	}

	linkInfo, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat replaced path: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("expected symlink path to be replaced with regular file, mode=%v", linkInfo.Mode())
	}
	replacedContent, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatalf("read replaced path: %v", err)
	}
	if string(replacedContent) != "replacement" {
		t.Fatalf("unexpected replaced file content: %q", string(replacedContent))
	}
}
