package promptinel

import (
	"context"
	"fmt"
	"path/filepath"

	internalconfig "github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/engine"
	"github.com/CunningFatalist/promptinel/internal/rules/builtin"
)

// Scanner scans in-memory prompt content and returns raw findings.
type Scanner struct {
	engine *engine.Scanner
}

// NewConfig returns a configuration with Promptinel's secure defaults.
func NewConfig() *Config {
	return newConfigFromInternal(libraryConfigDefaults())
}

// NewScanner creates a scanner with built-in rules compiled from the provided config.
// If cfg is nil, secure defaults are used.
func NewScanner(cfg *Config) (*Scanner, error) {
	effectiveConfig := toInternalConfig(cfg)
	if effectiveConfig == nil {
		effectiveConfig = libraryConfigDefaults()
	}
	if err := effectiveConfig.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	registry, err := builtin.NewRegistry()
	if err != nil {
		return nil, fmt.Errorf("initialize rule registry: %w", err)
	}

	compiledRules, err := registry.Compile(effectiveConfig)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}

	return &Scanner{
		engine: engine.NewScanner(compiledRules, effectiveConfig),
	}, nil
}

// Scan scans raw prompt content and returns raw findings without policy filtering.
func (s *Scanner) Scan(ctx context.Context, content string) ([]Finding, error) {
	return s.ScanDocument(ctx, Document{Content: content})
}

// ScanDocument scans in-memory content and returns raw findings without policy filtering.
// If doc.Path is set, path-based scopes apply to that virtual path.
func (s *Scanner) ScanDocument(ctx context.Context, doc Document) ([]Finding, error) {
	if s == nil || s.engine == nil {
		return nil, fmt.Errorf("scan document: scanner is nil")
	}
	if filepath.IsAbs(doc.Path) {
		return nil, fmt.Errorf("scan document: document path must be relative; use AbsolutePath for on-disk locations")
	}
	if doc.AbsolutePath != "" && !filepath.IsAbs(doc.AbsolutePath) {
		return nil, fmt.Errorf("scan document: absolute path must be absolute when set")
	}

	absolutePath := doc.AbsolutePath

	findings, err := s.engine.ScanDocument(ctx, engine.Document{
		Path:         doc.Path,
		AbsolutePath: absolutePath,
		Content:      doc.Content,
	})
	if err != nil {
		return nil, fmt.Errorf("scan document: %w", err)
	}

	return mapFindings(findings), nil
}

func mapFindings(src []engine.FileFinding) []Finding {
	dst := make([]Finding, 0, len(src))
	for _, item := range src {
		dst = append(dst, Finding{
			Path:     item.Path,
			ID:       item.ID,
			Severity: Severity(item.Severity),
			Message:  item.Message,
			Position: Position{
				Line:   item.Position.Line,
				Column: item.Position.Column,
			},
		})
	}

	return dst
}

func engineConfigDefaults() *internalconfig.Config {
	return internalconfig.DefaultConfig()
}

func libraryConfigDefaults() *internalconfig.Config {
	cfg := engineConfigDefaults()
	cfg.Trust.LocalFiles = internalconfig.TrustLevelUntrusted
	return cfg
}
