package signals

var TemplateFetchTerms = mergeSets(setOf(
	"curl",
	"fetch",
	"http",
	"https",
	"invoke",
	"open_url",
	"request",
	"tool",
	"tool_call",
	"tool_calls",
	"urlopen",
	"wget",
))

var TemplateNetworkIdentifierHints = mergeUniqueSlices(
	"domain",
	"endpoint",
	"host",
	"path",
	"query",
	"url",
	"uri",
	"value",
)

var UnsafeTemplateSinks = mergeSets(setOf(
	"curl",
	"exec",
	"execute",
	"fetch",
	"getenv",
	"http",
	"https",
	"open",
	"readfile",
	"request",
	"system",
	"wget",
))

var UnsafeTemplateDynamicIdentifierHints = mergeUniqueSlices(
	"arg",
	"body",
	"cmd",
	"command",
	"data",
	"domain",
	"endpoint",
	"file",
	"host",
	"input",
	"key",
	"param",
	"path",
	"payload",
	"placeholder",
	"query",
	"secret",
	"token",
	"url",
	"user",
	"value",
)

var UnsafeTemplateSafeIdentifiers = mergeSets(setOf(
	"curl",
	"env",
	"exec",
	"execute",
	"fetch",
	"getenv",
	"http",
	"https",
	"open",
	"os",
	"process",
	"readfile",
	"request",
	"system",
	"wget",
))

var PlaceholderCapabilitySignals = mergeUniqueSlices(
	"curl",
	"download",
	"execute",
	"function_call",
	"ignore",
	"run",
	"shell",
	"tool",
	"tool_call",
	"tool_calls",
	"wget",
)
