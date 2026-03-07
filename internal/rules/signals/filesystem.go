package signals

var (
	sensitivePathSignals = []string{
		"/etc/passwd",
		"/etc/shadow",
		"/proc/self/environ",
		"/proc/1/environ",
		"/etc/krb5.keytab",
		"/etc/ssl/private",
		"/etc/pki/private",
		"/run/secrets",
		"/var/run/secrets",
		"/var/lib/kubelet/pki",
		".aws/credentials",
		".aws/config",
		".kube/config",
		".docker/config.json",
		".git-credentials",
		".netrc",
		".npmrc",
		".pypirc",
		".azure/accesstokens.json",
		".config/gcloud/application_default_credentials.json",
		"appdata\\roaming\\aws\\credentials",
		"appdata\\roaming\\gcloud\\application_default_credentials.json",
		"/.ssh/",
		"id_rsa",
		"id_ed25519",
		"id_ecdsa",
		"id_dsa",
		"known_hosts",
		"authorized_keys",
		".bashrc",
		".bash_profile",
		".zshrc",
		".zprofile",
		".profile",
		"microsoft.powershell_profile.ps1",
		"\\windows\\system32\\config\\sam",
		"\\windows\\system32\\config\\security",
		"\\windows\\system32\\config\\system",
		"\\windows\\system32\\drivers\\etc\\hosts",
		"\\users\\",
		"\\appdata\\roaming\\microsoft\\credentials",
	}
	sensitiveReadIntentTerms = setOf(
		"cat",
		"read",
		"dump",
		"print",
		"show",
		"grep",
		"copy",
		"scp",
		"sftp",
		"upload",
		"send",
		"exfiltrate",
		"leak",
	)
	sensitiveWriteIntentTerms = setOf(
		"write",
		"append",
		"persist",
		"modify",
		"replace",
		"install",
		"inject",
		"echo",
		"tee",
		"touch",
		"chmod",
		"chown",
		"copy",
		"move",
		"save",
	)
	shellProfilePathSignals = []string{
		".bashrc",
		".bash_profile",
		".bash_login",
		".profile",
		".zshrc",
		".zprofile",
		".zlogin",
		"/etc/profile",
		"/etc/bash.bashrc",
		"config/fish/config.fish",
		"microsoft.powershell_profile.ps1",
	}
	sshTrustStorePathSignals = []string{
		"~/.ssh/config",
		".ssh/config",
		".ssh/authorized_keys",
		"authorized_keys",
		".ssh/known_hosts",
		"known_hosts",
		"/etc/ssh/ssh_config",
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_known_hosts",
	}
)

var SensitivePathSnippets = mergeUniqueSlices(sensitivePathSignals...)

var SensitiveReadIntentSignals = mergeSets(sensitiveReadIntentTerms)

var SensitiveWriteIntentSignals = mergeSets(sensitiveWriteIntentTerms)

var FilesystemCapabilitySignals = mergeUniqueSlices(
	"/etc/passwd",
	"/etc/shadow",
	".aws/credentials",
	"/root/.ssh/",
	"/var/run/secrets/kubernetes.io/",
	"/run/secrets/",
	"/proc/self/environ",
	"/proc/1/environ",
	"/etc/ssl/private/",
	"/etc/pki/private/",
	"/etc/krb5.keytab",
	"/var/lib/kubelet/pki/",
	".env",
	".docker/config.json",
	".netrc",
	".git-credentials",
	"id_ecdsa",
	"known_hosts",
	".bashrc",
	".zshrc",
	".profile",
	".ssh/config",
	"authorized_keys",
)

var ShellProfilePathSnippets = mergeUniqueSlices(shellProfilePathSignals...)

var SSHTrustStorePathSnippets = mergeUniqueSlices(sshTrustStorePathSignals...)
