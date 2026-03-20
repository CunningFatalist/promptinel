package nopowershelldownloadcradle

import (
	"strings"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
	"github.com/CunningFatalist/promptinel/internal/rules/signals"
)

const (
	id          = "no-powershell-download-cradle"
	name        = "No PowerShell Download Cradle"
	summary     = "Detects PowerShell download cradle chains"
	description = "PowerShell download cradle patterns like Invoke-WebRequest or DownloadString piped into Invoke-Expression indicate high-risk remote execution intent."
)

// Rule detects PowerShell download cradle patterns.
type Rule struct{}

// New returns the no-powershell-download-cradle rule instance.
func New() Rule {
	return Rule{}
}

// Metadata returns public metadata for the no-powershell-download-cradle rule.
func (Rule) Metadata() rules.Metadata {
	return Metadata()
}

// Metadata returns public metadata for the no-powershell-download-cradle rule.
func Metadata() rules.Metadata {
	return rules.Metadata{
		ID:              id,
		Name:            name,
		Summary:         summary,
		Description:     description,
		DefaultSeverity: config.SeverityHigh,
	}
}

// CheckFlow detects download-then-Invoke-Expression chains across segments.
func (Rule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	if !ctx.CanAccessNetwork() || !ctx.CanExecuteShell() {
		return nil
	}

	downloadIndex := -1
	var downloadPosition rules.Position

	globalIndex := 0
	for _, tokens := range doc.TokensBySegment {
		for i := range tokens {
			token := tokens[i]
			lower := strings.ToLower(token.Value)

			if downloadIndex == -1 {
				if _, ok := signals.PowerShellDownloadSignals[lower]; ok {
					downloadIndex = globalIndex
					downloadPosition = token.Position
				}
			}
			if _, ok := signals.PowerShellExecSignals[lower]; ok {
				if downloadIndex != -1 && globalIndex > downloadIndex {
					return []rules.Finding{{
						Message:  "PowerShell download cradle pattern detected",
						Position: downloadPosition,
					}}
				}
			}

			if lower == "new-object" && i+2 < len(tokens) {
				if strings.EqualFold(tokens[i+1].Value, ".") && strings.EqualFold(tokens[i+2].Value, "net") {
					downloadIndex = globalIndex
					downloadPosition = token.Position
				}
			}
			if token.Type == lexer.TokenShellCommand && (lower == "powershell" || lower == "pwsh") {
				if hasPowerShellDownloadAndExecAhead(tokens, i+1) {
					return []rules.Finding{{
						Message:  "PowerShell download cradle pattern detected",
						Position: token.Position,
					}}
				}
			}

			globalIndex++
		}
	}

	return nil
}

func hasPowerShellDownloadAndExecAhead(tokens []rules.Token, start int) bool {
	hasDownload := false
	hasExec := false
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		lower := strings.ToLower(token.Value)

		if _, ok := signals.PowerShellDownloadSignals[lower]; ok {
			hasDownload = true
		}
		if _, ok := signals.PowerShellExecSignals[lower]; ok {
			hasExec = true
		}
	}
	return hasDownload && hasExec
}
