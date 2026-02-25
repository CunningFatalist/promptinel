package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Builtin_NewRegistry_ContainsDefaultRules(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	list := registry.List()
	expectedIDs := []string{
		"no-bidi-control-characters",
		"no-command-chaining",
		"no-curl-pipe-shell",
		"no-data-uri-payloads",
		"no-download-execute",
		"no-hidden-html-instructions",
		"no-insecure-http",
		"no-metadata-service-access",
		"no-override-capability-flow",
		"no-prompt-injection-override",
		"no-secret-exfiltration-intent",
		"no-secret-to-network-flow",
		"no-sensitive-file-paths",
		"no-staged-download-execution",
		"no-suspicious-base64",
		"no-unsafe-templates",
		"no-zero-width",
	}
	require.Len(t, list, len(expectedIDs))
	for i, id := range expectedIDs {
		assert.Equal(t, id, list[i].ID)
	}
}

func Test_Builtin_NewRegistry_DescribeKnownRule(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	meta, ok := registry.Describe("no-zero-width")
	require.True(t, ok)
	assert.Equal(t, "No Zero Width Characters", meta.Name)
}
