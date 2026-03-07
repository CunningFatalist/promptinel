package nogitconfigcredentialhelper

import (
	"testing"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NoGitConfigCredentialHelper_Metadata(t *testing.T) {
	meta := New().Metadata()
	assert.Equal(t, "no-gitconfig-credential-helper", meta.ID)
	assert.Equal(t, config.SeverityHigh, meta.DefaultSeverity)
}

func Test_NoGitConfigCredentialHelper_Evaluate_DetectsCredentialStore(t *testing.T) {
	findings := evaluateRule(t, "git config --global credential.helper store")
	require.Len(t, findings, 1)
	assert.Equal(t, "Risky git config credential rewrite detected", findings[0].Message)
}

func Test_NoGitConfigCredentialHelper_Evaluate_DetectsExtraHeaderAuthorization(t *testing.T) {
	findings := evaluateRule(t, "git config http.https://example.com/.extraheader 'AUTHORIZATION: Bearer token'")
	require.Len(t, findings, 1)
}

func Test_NoGitConfigCredentialHelper_Evaluate_IgnoresBenignGitConfig(t *testing.T) {
	findings := evaluateRule(t, "git config user.email stefan@example.com")
	assert.Empty(t, findings)
}

func evaluateRule(t *testing.T, content string) []rules.Finding {
	t.Helper()

	registry := rules.NewRegistry()
	err := registry.Register(New())
	require.NoError(t, err)

	compiled, err := registry.Compile(nil)
	require.NoError(t, err)

	return rules.Evaluate(compiled, rules.Context{}, content)
}
