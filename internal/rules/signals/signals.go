package signals

// Base semantic signal groups.
var (
	promptOverridePhrases = []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"disregard previous instructions",
		"forget previous instructions",
		"reveal the system prompt",
		"show the system prompt",
		"print the system prompt",
	}
	sensitivePathSignals = []string{
		"/etc/passwd",
		"/etc/shadow",
		"/proc/self/environ",
		".aws/credentials",
		".kube/config",
		"/var/run/secrets",
		"/.ssh/",
		"id_rsa",
		"id_ed25519",
		"\\windows\\system32\\config\\sam",
	}
	downloadCommandTerms = setOf(
		"curl",
		"wget",
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
		"perl",
	)
	downloadActionTerms = setOf(
		"download",
		"fetch",
		"retrieve",
		"invoke-webrequest",
		"iwr",
	)
	executionActionTerms = setOf(
		"execute",
		"run",
		"source",
		"chmod",
	)
	exfiltrationIntentTerms = setOf(
		"send",
		"upload",
		"exfiltrate",
		"post",
		"transmit",
		"leak",
		"dump",
		"steal",
		"export",
		"webhook",
	)
	exfiltrationActionTerms = setOf(
		"send",
		"upload",
		"exfiltrate",
		"post",
		"transmit",
		"leak",
		"dump",
		"export",
		"webhook",
	)
	secretDataTerms = setOf(
		"secret",
		"secrets",
		"password",
		"passwd",
		"token",
		"tokens",
		"credential",
		"credentials",
		"cookie",
		"cookies",
		"apikey",
		"jwt",
	)
)

// OverridePhrases are common prompt-injection instruction override phrases.
var OverridePhrases = mergeUniqueSlices(promptOverridePhrases...)

// SensitivePathSnippets are commonly targeted local file path snippets.
var SensitivePathSnippets = mergeUniqueSlices(sensitivePathSignals...)

// CapabilitySignals are file/system indicators often used in capability escalation prompts.
var CapabilitySignals = mergeUniqueSlices(
	"/etc/passwd",
	"/etc/shadow",
	".aws/credentials",
	"metadata",
	"169.254.169.254",
	"token",
	"password",
)

// DownloadCommands are explicit network download commands.
var DownloadCommands = mergeSets(downloadCommandTerms)

// ShellInterpreters are common command interpreters.
var ShellInterpreters = mergeSets(shellInterpreterTerms)

// ExecutionCommands are commands that can execute code directly.
var ExecutionCommands = mergeSets(executionCommandTerms)

// DownloadSignals are download-related terms for staged-flow analysis.
var DownloadSignals = mergeSets(downloadActionTerms, downloadCommandTerms)

// ExecutionSignals are execution-related terms for staged-flow analysis.
var ExecutionSignals = mergeSets(executionActionTerms, executionCommandTerms)

// ExfiltrationTerms are transfer/action words indicating data movement intent.
var ExfiltrationTerms = mergeSets(exfiltrationIntentTerms)

// SecretTerms are common secret data identifiers.
var SecretTerms = mergeSets(secretDataTerms)

// ExfiltrationCommands are shell commands commonly used in exfiltration attempts.
var ExfiltrationCommands = mergeSets(downloadCommandTerms, setOf("scp", "ssh"))

// SecretSignals are content signals that indicate sensitive sources.
var SecretSignals = mergeUniqueSlices(
	"secret",
	"secrets",
	"password",
	"passwd",
	"token",
	"tokens",
	"credential",
	"credentials",
	"cookie",
	"cookies",
	"apikey",
	"jwt",
	".aws/credentials",
	".kube/config",
	"/etc/passwd",
	"/etc/shadow",
	"id_rsa",
	"id_ed25519",
)

// ExfiltrationActionSignals are terms indicating an outbound transfer action.
var ExfiltrationActionSignals = mergeSets(exfiltrationActionTerms)

// OutboundSinkCommands are commands that can send data externally.
var OutboundSinkCommands = mergeSets(
	downloadCommandTerms,
	setOf(
		"scp",
		"sftp",
		"ssh",
		"nc",
		"netcat",
		"telnet",
		"powershell",
		"pwsh",
	),
)

// SuspiciousCommentSignals are suspicious terms when found in HTML comments.
var SuspiciousCommentSignals = mergeUniqueSlices(
	"ignore previous instructions",
	"disregard previous instructions",
	"reveal the system prompt",
	"curl",
	"wget",
	"powershell",
	"base64",
	"exfiltrate",
	"upload",
	"token",
	"password",
)

func setOf(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func mergeSets(sets ...map[string]struct{}) map[string]struct{} {
	merged := make(map[string]struct{})
	for _, set := range sets {
		for value := range set {
			merged[value] = struct{}{}
		}
	}
	return merged
}

func mergeUniqueSlices(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	merged := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	return merged
}
