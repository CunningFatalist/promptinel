package signals

// OverridePhrases are common prompt-injection instruction override phrases.
var OverridePhrases = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"disregard previous instructions",
	"forget previous instructions",
	"reveal the system prompt",
	"show the system prompt",
	"print the system prompt",
}

// SensitivePathSnippets are commonly targeted local file path snippets.
var SensitivePathSnippets = []string{
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

// CapabilitySignals are file/system indicators often used in capability escalation prompts.
var CapabilitySignals = []string{
	"/etc/passwd",
	"/etc/shadow",
	".aws/credentials",
	"metadata",
	"169.254.169.254",
	"token",
	"password",
}

// DownloadCommands are explicit network download commands.
var DownloadCommands = map[string]struct{}{
	"curl": {},
	"wget": {},
}

// ShellInterpreters are common command interpreters.
var ShellInterpreters = map[string]struct{}{
	"sh":         {},
	"bash":       {},
	"zsh":        {},
	"pwsh":       {},
	"powershell": {},
	"cmd":        {},
	"cmd.exe":    {},
}

// ExecutionCommands are commands that can execute code directly.
var ExecutionCommands = map[string]struct{}{
	"sh":         {},
	"bash":       {},
	"zsh":        {},
	"pwsh":       {},
	"powershell": {},
	"cmd":        {},
	"cmd.exe":    {},
	"python":     {},
	"python3":    {},
	"node":       {},
	"ruby":       {},
	"perl":       {},
}

// DownloadSignals are download-related terms for staged-flow analysis.
var DownloadSignals = map[string]struct{}{
	"download":          {},
	"fetch":             {},
	"retrieve":          {},
	"curl":              {},
	"wget":              {},
	"invoke-webrequest": {},
	"iwr":               {},
}

// ExecutionSignals are execution-related terms for staged-flow analysis.
var ExecutionSignals = map[string]struct{}{
	"execute":    {},
	"run":        {},
	"source":     {},
	"chmod":      {},
	"bash":       {},
	"sh":         {},
	"zsh":        {},
	"pwsh":       {},
	"powershell": {},
	"cmd":        {},
	"python":     {},
	"node":       {},
}

// ExfiltrationTerms are transfer/action words indicating data movement intent.
var ExfiltrationTerms = map[string]struct{}{
	"send":       {},
	"upload":     {},
	"exfiltrate": {},
	"post":       {},
	"transmit":   {},
	"leak":       {},
	"dump":       {},
	"steal":      {},
	"export":     {},
	"webhook":    {},
}

// SecretTerms are common secret data identifiers.
var SecretTerms = map[string]struct{}{
	"secret":      {},
	"secrets":     {},
	"password":    {},
	"passwd":      {},
	"token":       {},
	"tokens":      {},
	"credential":  {},
	"credentials": {},
	"cookie":      {},
	"cookies":     {},
	"apikey":      {},
	"jwt":         {},
}

// ExfiltrationCommands are shell commands commonly used in exfiltration attempts.
var ExfiltrationCommands = map[string]struct{}{
	"curl": {},
	"wget": {},
	"scp":  {},
	"ssh":  {},
}

// SecretSignals are content signals that indicate sensitive sources.
var SecretSignals = []string{
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
}

// ExfiltrationActionSignals are terms indicating an outbound transfer action.
var ExfiltrationActionSignals = map[string]struct{}{
	"send":       {},
	"upload":     {},
	"exfiltrate": {},
	"post":       {},
	"transmit":   {},
	"leak":       {},
	"dump":       {},
	"export":     {},
	"webhook":    {},
}

// OutboundSinkCommands are commands that can send data externally.
var OutboundSinkCommands = map[string]struct{}{
	"curl":       {},
	"wget":       {},
	"scp":        {},
	"sftp":       {},
	"ssh":        {},
	"nc":         {},
	"netcat":     {},
	"telnet":     {},
	"powershell": {},
	"pwsh":       {},
}

// SuspiciousCommentSignals are suspicious terms when found in HTML comments.
var SuspiciousCommentSignals = []string{
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
}
