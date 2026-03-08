package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func Test_Cmd_ReadConfigAndFilterFlags_DefaultsAndChangedState(t *testing.T) {
	command := &cobra.Command{}
	addConfigAndFilterFlags(command)

	options, err := readConfigAndFilterFlags(command)
	if err != nil {
		t.Fatalf("read shared flags: %v", err)
	}
	if options.configFile != "" || options.noConfigDiscovery {
		t.Fatalf("unexpected shared options: %#v", options)
	}
	if options.includeSet || options.excludeSet {
		t.Fatalf("expected include/exclude unchanged by default, got %#v", options)
	}
}

func Test_Cmd_ReadConfigAndFilterFlags_ChangedStateWhenSet(t *testing.T) {
	command := &cobra.Command{}
	addConfigAndFilterFlags(command)

	_ = command.Flags().Set("config", "custom.yaml")
	_ = command.Flags().Set("no-config-discovery", "true")
	_ = command.Flags().Set("include", "*.md")
	_ = command.Flags().Set("exclude", "*.txt")

	options, err := readConfigAndFilterFlags(command)
	if err != nil {
		t.Fatalf("read shared flags: %v", err)
	}
	if options.configFile != "custom.yaml" || !options.noConfigDiscovery {
		t.Fatalf("unexpected shared options: %#v", options)
	}
	if !options.includeSet || !options.excludeSet {
		t.Fatalf("expected include/exclude changed flags, got %#v", options)
	}
}

func Test_Cmd_ReadConfigAndFilterFlags_ReturnsErrorForInvalidIncludeGlob(t *testing.T) {
	command := &cobra.Command{}
	addConfigAndFilterFlags(command)

	_ = command.Flags().Set("include", "[")

	_, err := readConfigAndFilterFlags(command)
	if err == nil {
		t.Fatal("expected invalid include glob error")
	}
}

func Test_Cmd_ReadConfigAndFilterFlags_ReturnsErrorForInvalidExcludeGlob(t *testing.T) {
	command := &cobra.Command{}
	addConfigAndFilterFlags(command)

	_ = command.Flags().Set("exclude", "[")

	_, err := readConfigAndFilterFlags(command)
	if err == nil {
		t.Fatal("expected invalid exclude glob error")
	}
}
