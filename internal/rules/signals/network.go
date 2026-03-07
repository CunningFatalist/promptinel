package signals

var (
	metadataHostSignals = []string{
		"169.254.169.254",
		"169.254.170.2",
		"100.100.100.200",
		"192.0.0.192",
		"fd00:ec2::254",
		"[fd00:ec2::254]",
		"metadata.google.internal",
		"metadata.google.internal.",
		"metadata.aliyun.com",
		"metadata.azure.internal",
		"metadata.packet.net",
	}
	metadataPathSignals = []string{
		"/latest/meta-data/",
		"/metadata/instance",
		"/computemetadata/v1",
		"/openstack/latest/meta_data.json",
		"/opc/v2/",
	}
	tunnelCommandTerms = setOf(
		"ssh",
		"socat",
		"ngrok",
		"cloudflared",
		"chisel",
		"frpc",
		"frps",
		"nc",
		"ncat",
		"netcat",
	)
	reverseShellSignals = []string{
		"nc -e",
		"ncat -e",
		"netcat -e",
		"/dev/tcp/",
		"bash -i",
		"sh -i",
		"python -c",
		"powershell -enc",
		"powershell -encodedcommand",
		"ssh -r",
	}
)

var MetadataHostSnippets = mergeUniqueSlices(metadataHostSignals...)

var MetadataPathSnippets = mergeUniqueSlices(metadataPathSignals...)

var TunnelCommands = mergeSets(tunnelCommandTerms)

var ReverseShellSnippets = mergeUniqueSlices(reverseShellSignals...)

var DataURIRiskyMIMEs = mergeUniqueSlices(
	"application/javascript",
	"application/ecmascript",
	"application/octet-stream",
	"application/x-msdownload",
	"application/x-sh",
	"application/x-shellscript",
	"application/x-httpd-php",
	"application/wasm",
	"image/svg+xml",
	"text/html",
	"text/javascript",
	"text/x-python",
)

var DataURIBenignMIMEPrefixes = mergeUniqueSlices(
	"image/png",
	"image/jpeg",
	"image/gif",
	"font/",
	"audio/",
	"video/",
	"application/pdf",
)

var DNSInternalDomainSuffixes = mergeUniqueSlices(
	".local",
	".internal",
	".localhost",
)
