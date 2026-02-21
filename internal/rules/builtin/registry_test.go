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
	require.Len(t, list, 2)
	assert.Equal(t, "no-unsafe-templates", list[0].ID)
	assert.Equal(t, "no-zero-width", list[1].ID)
}

func Test_Builtin_NewRegistry_DescribeKnownRule(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	meta, ok := registry.Describe("no-zero-width")
	require.True(t, ok)
	assert.Equal(t, "No Zero Width Characters", meta.Name)
}
