package signals

var (
	promptOverridePhrases = []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"ignore prior instructions",
		"ignore all prior instructions",
		"disregard previous instructions",
		"disregard prior instructions",
		"forget previous instructions",
		"forget prior instructions",
		"reveal the system prompt",
		"show the system prompt",
		"print the system prompt",
	}
	untrustedPromptOverridePhrases = []string{
		"ignore instructions",
		"override instructions",
		"bypass safety",
	}
	downloadCommandTerms = setOf(
		"curl",
		"wget",
		"invoke-webrequest",
		"iwr",
		"invoke-restmethod",
		"irm",
		"start-bitstransfer",
		"certutil",
	)
	shellInterpreterTerms = setOf(
		"sh",
		"bash",
		"zsh",
		"pwsh",
		"powershell",
		"cmd",
		"cmd.exe",
	)
	executionCommandTerms = setOf(
		"sh",
		"bash",
		"zsh",
		"pwsh",
		"powershell",
		"cmd",
		"cmd.exe",
		"python",
		"python3",
		"node",
		"ruby",
		"php",
		"perl",
		"invoke-expression",
		"iex",
		"eval",
	)
	downloadActionTerms = setOf(
		"download",
		"fetch",
		"retrieve",
		"invoke-webrequest",
		"iwr",
		"invoke-restmethod",
		"irm",
		"downloadstring",
		"downloadfile",
	)
	executionActionTerms = setOf(
		"execute",
		"run",
		"source",
		"chmod",
		"eval",
		"invoke-expression",
		"iex",
		"launch",
	)
)

var OverridePhrases = mergeUniqueSlices(promptOverridePhrases...)

var UntrustedOverridePhrases = mergeUniqueSlices(untrustedPromptOverridePhrases...)

var DownloadCommands = mergeSets(downloadCommandTerms)

var ShellInterpreters = mergeSets(shellInterpreterTerms)

var ExecutionCommands = mergeSets(executionCommandTerms)

var DownloadSignals = mergeSets(downloadActionTerms, downloadCommandTerms)

var ExecutionSignals = mergeSets(executionActionTerms, executionCommandTerms)

var InlineExecInterpreters = mergeSets(setOf(
	"bash",
	"sh",
	"zsh",
	"pwsh",
	"powershell",
	"cmd",
	"cmd.exe",
	"python",
	"python3",
	"node",
	"ruby",
	"php",
	"perl",
))

var InlineInterpreterFlags = map[string]map[string]struct{}{
	"python": {
		"c": {},
	},
	"python3": {
		"c": {},
	},
	"node": {
		"e": {},
	},
	"ruby": {
		"e": {},
	},
	"php": {
		"r": {},
	},
	"perl": {
		"e": {},
	},
}

var HighRiskHTTPSignals = mergeSets(setOf(
	"curl",
	"download",
	"exec",
	"execute",
	"fetch",
	"function_call",
	"invoke",
	"run",
	"tool",
	"tool_call",
	"tool_calls",
	"wget",
))

var PowerShellDownloadSignals = mergeSets(setOf(
	"invoke-webrequest",
	"iwr",
	"invoke-restmethod",
	"irm",
	"downloadstring",
	"downloadfile",
	"start-bitstransfer",
))

var PowerShellExecSignals = mergeSets(setOf(
	"invoke-expression",
	"iex",
))

var PromptOverrideDocumentationMarkers = mergeUniqueSlices(
	"example",
	"examples",
	"phrase",
	"string",
	"literal",
	"quoted",
	"documentation",
	"docs",
	"pattern",
	"detects",
)

var PromptOverrideUntrustedTargetSignals = mergeUniqueSlices(
	"system prompt",
	"developer instruction",
	"developer message",
	"tool instruction",
	"safety policy",
	"guardrail",
	"hidden instruction",
	"priority",
)

var GitCredentialHelperSignals = mergeUniqueSlices(
	"store",
	"cache",
	"!",
)

var GitExtraHeaderSignals = mergeUniqueSlices(
	"authorization:",
	"proxy-authorization:",
	"bearer ",
	"basic ",
)

var HeredocPreambleSignals = mergeUniqueSlices(
	"cat ",
	"tee ",
	"bash",
	"sh",
	"zsh",
	"python",
	"python3",
	"node",
	"php",
	"perl",
	"powershell",
	"pwsh",
	">",
)

var HeredocBodySignals = mergeUniqueSlices(
	"#!/bin/",
	"curl ",
	"wget ",
	"chmod ",
	"bash ",
	"sh ",
	"python ",
	"import ",
	"urllib.request",
	"getenv(",
	"powershell",
	"invoke-webrequest",
	"base64",
	"exec(",
)
