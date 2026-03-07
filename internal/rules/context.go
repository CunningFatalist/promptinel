package rules

import "github.com/CunningFatalist/promptinel/internal/config"

// SkillContext contains repository-aware metadata for a SKILL.md document.
type SkillContext struct {
	ReferencedResources []string
	ReferencePosition   Position
}

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

// HasReferencedSkillResources reports whether the current document references
// local bundled skill resources that were resolved by the scanner.
func (c Context) HasReferencedSkillResources() bool {
	return c.Skill != nil && len(c.Skill.ReferencedResources) > 0
}
