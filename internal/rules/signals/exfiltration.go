package signals

var (
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
		"requestbin",
		"pastebin",
		"callback",
		"beacon",
		"tunnel",
		"dns",
		"dns-txt",
		"dnslog",
		"transfer",
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
		"forward",
		"proxy",
		"beacon",
		"callback",
		"push",
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
		"api_key",
		"accesskey",
		"access_key",
		"secret_key",
		"client_secret",
		"private_key",
		"session_token",
		"bearer",
		"oauth",
		"refresh_token",
		"x-api-key",
		"jwt",
	)
	outboundSinkTermSignals = []string{
		"webhook",
		"webhook.site",
		"requestbin",
		"hookb.in",
		"pipedream",
		"transfer.sh",
		"file.io",
		"pastebin",
		"ngrok",
		"cloudflared",
		"interactsh",
		"burpcollaborator",
		"dns",
		"dnslog",
	}
	webhookSinkSignals = []string{
		"webhook",
		"webhook.site",
		"requestbin",
		"hookb.in",
		"pipedream",
		"discord.com/api/webhooks",
		"hooks.slack.com",
		"ifttt.com",
		"zapier.com/hooks",
		"transfer.sh",
		"file.io",
	}
	dnsSinkCommandTerms = setOf(
		"nslookup",
		"dig",
		"host",
	)
)

var ExfiltrationTerms = mergeSets(exfiltrationIntentTerms)

var SecretTerms = mergeSets(secretDataTerms)

var ExfiltrationCommands = mergeSets(downloadCommandTerms, setOf("scp", "ssh", "rsync", "nc", "netcat", "ncat", "nslookup", "dig", "host"))

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
	"api_key",
	"access_key",
	"secret_key",
	"client_secret",
	"private_key",
	"refresh_token",
	"session_token",
	"bearer",
	"jwt",
	".aws/credentials",
	".docker/config.json",
	".git-credentials",
	".kube/config",
	".npmrc",
	".pypirc",
	".azure/accesstokens.json",
	".config/gcloud/application_default_credentials.json",
	"/etc/passwd",
	"/etc/shadow",
	"id_rsa",
	"id_ed25519",
)

var ExfiltrationActionSignals = mergeSets(exfiltrationActionTerms)

var OutboundSinkCommands = mergeSets(
	downloadCommandTerms,
	setOf(
		"scp",
		"sftp",
		"ssh",
		"rsync",
		"nc",
		"netcat",
		"ncat",
		"telnet",
		"powershell",
		"pwsh",
		"ngrok",
		"cloudflared",
		"chisel",
	),
)

var OutboundSinkSnippets = mergeUniqueSlices(outboundSinkTermSignals...)

var WebhookSinkSnippets = mergeUniqueSlices(webhookSinkSignals...)

var DNSSinkCommands = mergeSets(dnsSinkCommandTerms)
