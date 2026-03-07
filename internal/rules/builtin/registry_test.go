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
		"no-dns-exfiltration",
		"no-download-execute",
		"no-gitconfig-credential-helper",
		"no-hidden-directionality",
		"no-hidden-html-instructions",
		"no-insecure-http",
		"no-interpreter-inline-exec",
		"no-metadata-service-access",
		"no-mixed-script-identifiers",
		"no-multilayer-encoding",
		"no-nonstandard-whitespace",
		"no-override-capability-flow",
		"no-powershell-download-cradle",
		"no-prompt-injection-override",
		"no-role-header-spoofing",
		"no-secret-exfiltration-intent",
		"no-secret-to-network-flow",
		"no-sensitive-file-paths",
		"no-shell-heredoc-payload",
		"no-shell-profile-modification",
		"no-ssh-config-manipulation",
		"no-staged-download-execution",
		"no-suspicious-base64",
		"no-tainted-placeholder-instructions",
		"no-template-network-fetch",
		"no-transcript-injection",
		"no-tunnel-and-reverse-shell",
		"no-unsafe-templates",
		"no-url-encoded-command-payload",
		"no-webhook-exfiltration",
		"no-yaml-json-role-fields",
		"no-zero-width",
		"skill-has-bundled-resources",
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
