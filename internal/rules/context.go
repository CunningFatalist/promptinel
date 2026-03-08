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
	return config.TrustLevelAtLeast(c.TrustLevel, config.TrustLevelUntrusted)
}

// EffectiveTrustAt returns the effective trust at a byte offset.
func (c Context) EffectiveTrustAt(byteOffset int) config.TrustLevel {
	return c.EffectiveTrustRange(byteOffset, byteOffset+1)
}

// EffectiveTrustRange returns the lowest-trust level across a byte range.
func (c Context) EffectiveTrustRange(start int, end int) config.TrustLevel {
	if start < 0 {
		start = 0
	}
	if end <= start {
		end = start + 1
	}

	effective := c.TrustLevel
	for _, span := range c.TrustSpans {
		if span.End <= span.Start {
			continue
		}
		if span.End <= start || span.Start >= end {
			continue
		}
		effective = config.MoreRestrictiveTrustLevel(effective, span.TrustLevel)
	}

	return effective
}

// IsUntrustedAt reports whether the effective trust at a byte offset is untrusted or tainted.
func (c Context) IsUntrustedAt(byteOffset int) bool {
	return config.TrustLevelAtLeast(c.EffectiveTrustAt(byteOffset), config.TrustLevelUntrusted)
}

// IsUntrustedRange reports whether any part of the range is untrusted or tainted.
func (c Context) IsUntrustedRange(start int, end int) bool {
	return config.TrustLevelAtLeast(c.EffectiveTrustRange(start, end), config.TrustLevelUntrusted)
}

// IsTaintedAt reports whether the effective trust at a byte offset is tainted.
func (c Context) IsTaintedAt(byteOffset int) bool {
	return c.EffectiveTrustAt(byteOffset) == config.TrustLevelTainted
}

// IsTaintedRange reports whether any part of the range is tainted.
func (c Context) IsTaintedRange(start int, end int) bool {
	return c.EffectiveTrustRange(start, end) == config.TrustLevelTainted
}

// HasReferencedSkillResources reports whether the current document references
// local bundled skill resources that were resolved by the scanner.
func (c Context) HasReferencedSkillResources() bool {
	return c.Skill != nil && len(c.Skill.ReferencedResources) > 0
}
