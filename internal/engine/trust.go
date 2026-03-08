package engine

import (
	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
	"github.com/CunningFatalist/promptinel/internal/rules"
)

func deriveTrustSpans(content string, cfg *config.Config) []rules.TrustSpan {
	if cfg == nil {
		return nil
	}

	placeholderTrust := config.MoreRestrictiveTrustLevel(cfg.Trust.LocalFiles, cfg.Trust.UserInputPlaceholders)
	if placeholderTrust == cfg.Trust.LocalFiles {
		return nil
	}

	tokens := lexer.Classify(lexer.Lex(content))
	spans := make([]rules.TrustSpan, 0)
	for _, token := range tokens {
		if token.Type != lexer.TokenPlaceholder {
			continue
		}
		spans = append(spans, rules.TrustSpan{
			Start:      token.Start,
			End:        token.End,
			TrustLevel: placeholderTrust,
			Source:     rules.TrustSpanSourceUserInputPlaceholder,
		})
	}

	return spans
}
