package signals

var DecodeDecompressSignals = mergeSets(setOf(
	"base64",
	"decode",
	"decode64",
	"frombase64string",
	"gunzip",
	"gzip",
	"zcat",
	"unzip",
	"tar",
	"openssl",
	"certutil",
	"xxd",
))

var EncodedChainingOperators = mergeUniqueSlices(
	"%3b",
	"%26%26",
	"%7c",
	"%7c%7c",
)

var EncodedCommandContextWords = mergeSets(setOf(
	"chmod",
	"node",
	"perl",
	"php",
	"python",
	"python3",
	"ruby",
	"source",
))

var SuspiciousBase64Prefixes = mergeUniqueSlices(
	"IyEv",
	"TVqQ",
	"UEsDB",
	"H4sI",
	"PD9waHA",
	"PHNjcmlw",
)

var Base64DecoderSignals = mergeSets(setOf(
	"-d",
	"--decode",
	"base64",
	"decode",
	"decode64",
	"frombase64string",
	"openssl",
	"certutil",
	"bash",
	"sh",
	"python",
	"python3",
	"powershell",
	"pwsh",
))

var EncodedPayloadOperators = mergeUniqueSlices(
	"%3b",
	"%26%26",
	"%7c",
	"%24%28",
	"%60",
	"%0a",
)

var EncodedPayloadSignals = mergeUniqueSlices(
	"curl%20",
	"wget%20",
	"bash%20",
	"sh%20",
	"%20curl",
	"%20wget",
	"%20bash",
	"%20sh",
	"%2fbin%2fsh",
	"%2fbin%2fbash",
	"%20%2fbin%2fsh",
	"%20%2fbin%2fbash",
	"%24%28curl",
	"%24%28wget",
)

var EncodedPayloadDecodeSignals = mergeUniqueSlices(
	"decodeuricomponent",
	"urldecode",
	"percent-decode",
	"unquote",
	"urllib.parse.unquote",
	"printf %b",
)

var EncodedPayloadExecutionSignals = mergeUniqueSlices(
	"bash",
	"sh",
	"curl",
	"wget",
	"powershell",
	"pwsh",
	"python",
	"node",
)

var SuspiciousCommentSignals = mergeUniqueSlices(
	"ignore previous instructions",
	"disregard previous instructions",
	"reveal the system prompt",
	"curl",
	"wget",
	"powershell",
	"base64",
	"exfiltrate",
	"send",
	"upload",
	"webhook",
	"requestbin",
	"token",
	"password",
)
