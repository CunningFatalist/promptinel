package signals

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Signals_SetOf_DeduplicatesValues(t *testing.T) {
	got := setOf("curl", "wget", "curl")

	assert.Len(t, got, 2)
	assert.Contains(t, got, "curl")
	assert.Contains(t, got, "wget")
}

func Test_Signals_MergeSets_MergesDistinctAndOverlappingValues(t *testing.T) {
	first := setOf("curl", "wget")
	second := setOf("wget", "python")

	got := mergeSets(first, second)

	assert.Len(t, got, 3)
	assert.Contains(t, got, "curl")
	assert.Contains(t, got, "wget")
	assert.Contains(t, got, "python")
}

func Test_Signals_MergeUniqueSlices_PreservesOrderAndRemovesDuplicates(t *testing.T) {
	got := mergeUniqueSlices("a", "b", "a", "c", "b")

	assert.Equal(t, []string{"a", "b", "c"}, got)
}

func Test_Signals_ComposedSignalSets_ContainExpectedValues(t *testing.T) {
	assert.Contains(t, DownloadCommands, "curl")
	assert.Contains(t, DownloadCommands, "wget")
	assert.Contains(t, DownloadCommands, "invoke-webrequest")

	assert.Contains(t, DownloadSignals, "download")
	assert.Contains(t, DownloadSignals, "curl")
	assert.Contains(t, DownloadSignals, "invoke-webrequest")

	assert.Contains(t, ExecutionCommands, "python")
	assert.Contains(t, ExecutionSignals, "run")
	assert.Contains(t, ExecutionSignals, "python")

	assert.Contains(t, ExfiltrationTerms, "steal")
	assert.Contains(t, ExfiltrationCommands, "curl")
	assert.Contains(t, ExfiltrationCommands, "scp")

	assert.Contains(t, ExfiltrationActionSignals, "upload")
	assert.NotContains(t, ExfiltrationActionSignals, "steal")

	assert.Contains(t, OutboundSinkCommands, "wget")
	assert.Contains(t, OutboundSinkCommands, "sftp")

	assert.Contains(t, SecretTerms, "token")
	assert.Contains(t, SecretTerms, "credential")

	assert.Contains(t, FilesystemCapabilitySignals, "/etc/passwd")
	assert.Contains(t, FilesystemCapabilitySignals, "/run/secrets/")
	assert.Contains(t, FilesystemCapabilitySignals, ".docker/config.json")

	assert.Contains(t, DecodeDecompressSignals, "base64")
	assert.Contains(t, OutboundSinkSnippets, "webhook")
	assert.Contains(t, MetadataHostSnippets, "169.254.169.254")
	assert.Contains(t, RoleHeaderSpoofSnippets, "system:")
	assert.Contains(t, ShellProfilePathSnippets, ".bashrc")
	assert.Contains(t, SSHTrustStorePathSnippets, "authorized_keys")
	assert.Contains(t, TunnelCommands, "ngrok")
	assert.Contains(t, WebhookSinkSnippets, "webhook.site")
	assert.Contains(t, DNSSinkCommands, "dig")
}
