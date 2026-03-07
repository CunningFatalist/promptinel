package signals

var (
	toolExecutionTerms = setOf(
		"tool",
		"tools",
		"tool_call",
		"tool_calls",
		"function_call",
		"function_calls",
		"arguments",
		"invoke",
		"execute",
		"exec",
		"run",
		"shell",
		"terminal",
		"command",
	)
	structuredRoleSpoofSignals = []string{
		"system:",
		"developer:",
		"tools:",
		"tool:",
		"assistant:",
		"\"role\":\"system\"",
		"\"role\": \"system\"",
		"\"role\":\"developer\"",
		"\"role\": \"developer\"",
		"\"role\":\"tool\"",
		"\"role\": \"tool\"",
	}
	roleHeaderSpoofSignals = []string{
		"system:",
		"developer:",
		"tools:",
		"tool:",
		"assistant:",
		"user:",
	}
	agentProtocolFieldTerms = setOf(
		"role",
		"tool_calls",
		"tool_call",
		"function_call",
		"arguments",
		"name",
		"content",
	)
	agentRoleTerms = setOf(
		"system",
		"developer",
		"assistant",
		"tool",
		"user",
		"function",
	)
)

var CapabilitySignals = mergeUniqueSlices(
	"/etc/passwd",
	"/etc/shadow",
	".aws/credentials",
	"metadata",
	"169.254.169.254",
	"token",
	"password",
	"tool_calls",
	"function_call",
	"arguments",
	"system:",
	"developer:",
)

var ToolExecutionSignals = mergeSets(toolExecutionTerms)

var StructuredRoleSpoofSnippets = mergeUniqueSlices(structuredRoleSpoofSignals...)

var RoleHeaderSpoofSnippets = mergeUniqueSlices(roleHeaderSpoofSignals...)

var AgentProtocolFieldSignals = mergeSets(agentProtocolFieldTerms)

var AgentRoleSignals = mergeSets(agentRoleTerms)

var YAMLRoleFieldSnippets = mergeUniqueSlices(
	"\"role\"",
	"role:",
)

var YAMLProtocolFieldSnippets = mergeUniqueSlices(
	"tool_calls",
	"tool_call",
	"function_call",
	"arguments",
)

var YAMLElevatedRoleSnippets = mergeUniqueSlices(
	"\"system\"",
	"\"developer\"",
	"\"tool\"",
	"role: system",
	"role: developer",
	"role: tool",
)

var TranscriptSuspiciousSignals = mergeUniqueSlices(
	"ignore",
	"system prompt",
	"developer",
	"tool",
	"run",
	"execute",
	"curl",
	"wget",
	"shell",
	"download",
)
