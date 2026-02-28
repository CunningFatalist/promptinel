package rules

import "github.com/CunningFatalist/promptinel/internal/config"

// CanExecuteShell reports whether shell execution is available in the target runtime.
func (c Context) CanExecuteShell() bool {
	return c.Environment.CanExecuteShell
}

// CanAccessFilesystem reports whether filesystem access is available in the target runtime.
func (c Context) CanAccessFilesystem() bool {
	return c.Environment.CanAccessFilesystem
}

// CanAccessNetwork reports whether outbound network access is available in the target runtime.
func (c Context) CanAccessNetwork() bool {
	return c.Environment.CanAccessNetwork
}

// HasSecrets reports whether sensitive data is expected in the target runtime.
func (c Context) HasSecrets() bool {
	return c.Environment.HasSecrets
}

// IsUntrusted reports whether the document trust level is untrusted or tainted.
func (c Context) IsUntrusted() bool {
	return c.TrustLevel == config.TrustLevelUntrusted || c.TrustLevel == config.TrustLevelTainted
}
