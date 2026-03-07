package signals

import "regexp"

var (
	DataURIBase64Pattern = regexp.MustCompile(`(?i)data:([^\s;,]+)?(?:;[^\s;,=]+=[^\s;,]+)*;base64,([a-z0-9+/=]{32,})`)

	GitConfigPattern = regexp.MustCompile(`(?i)\bgit\s+config(?:\s+--(?:global|system|local))?\s+([^\s]+)\s+(.+)`)

	HiddenContainerStartPattern = regexp.MustCompile(`(?is)<([a-z0-9]+)\b[^>]*(?:hidden\b|aria-hidden\s*=\s*["']?true["']?|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'])[^>]*>`)

	TemplateContainerPattern = regexp.MustCompile(`(?is)<template\b[^>]*>(.*?)</template>`)

	RoleHeaderPattern = regexp.MustCompile(`(?im)^\s*(system|developer|tools|tool|assistant|user)\s*:`)

	HeredocStartPattern = regexp.MustCompile(`(?im)^.*<<-?\s*['"]?([a-z0-9_]+)['"]?.*$`)

	PlaceholderPattern = regexp.MustCompile(`\{\{[^}]+\}\}|\$\{[^}]+\}|<%[^%]+%>`)

	TranscriptRolePattern = regexp.MustCompile(`(?i)^\s*(user|assistant|system|developer|tool)\s*:\s*(.+)$`)
)
