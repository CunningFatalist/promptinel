package rules

import (
	"sort"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/lexer"
)

// Metadata describes a rule and how it should be presented to users.
type Metadata struct {
	ID              string
	Name            string
	Summary         string
	Description     string
	DefaultSeverity config.Severity
}

// Position describes where a finding occurred in a file.
type Position struct {
	Line   int
	Column int
}

// Context contains immutable input for rule evaluation.
type Context struct {
	Path        string
	Environment config.Environment
	TrustLevel  config.TrustLevel
	Skill       *SkillContext
}

// DocumentView is the normalized content and metadata for a single file.
type DocumentView struct {
	Path    string
	Content string
}

// SegmentType identifies a structural zone in a document.
type SegmentType string

const (
	SegmentTypePlainText SegmentType = "plain_text"
	SegmentTypeTemplate  SegmentType = "template"
)

// Segment is a structural chunk of a document.
type Segment struct {
	Type       SegmentType
	Content    string
	Position   Position
	ByteOffset int
}

// Token is a lexical unit inside a segment.
type Token struct {
	Value    string
	Type     lexer.TokenType
	Start    int
	End      int
	Position Position
}

// AnalyzedDocument is the phase output passed to flow rules.
type AnalyzedDocument struct {
	Document        DocumentView
	Segments        []Segment
	TokensBySegment [][]Token
}

// Finding is a single rule match.
type Finding struct {
	ID       string
	Severity config.Severity
	Message  string
	Position Position
}

// Rule defines metadata for a rule.
type Rule interface {
	Metadata() Metadata
}

// DocumentRule evaluates a whole document.
type DocumentRule interface {
	CheckDocument(ctx Context, doc DocumentView) []Finding
}

// SegmentRule evaluates each structural segment.
type SegmentRule interface {
	CheckSegment(ctx Context, segment Segment) []Finding
}

// TokenRule evaluates tokenized segment data.
type TokenRule interface {
	CheckTokens(ctx Context, segment Segment, tokens []Token) []Finding
}

// FlowRule evaluates the full analyzed document graph.
type FlowRule interface {
	CheckFlow(ctx Context, doc AnalyzedDocument) []Finding
}

type ruleEntry struct {
	metadata Metadata
	rule     Rule
}

// CompiledRule is a rule prepared for evaluation with final severity.
type CompiledRule struct {
	ID            string
	Severity      config.Severity
	checkDocument func(Context, DocumentView) []Finding
	checkSegment  func(Context, Segment) []Finding
	checkTokens   func(Context, Segment, []Token) []Finding
	checkFlow     func(Context, AnalyzedDocument) []Finding
}

// Evaluate runs all compiled rules deterministically.
func Evaluate(compiled []CompiledRule, ctx Context, content string) []Finding {
	doc := DocumentView{
		Path:    ctx.Path,
		Content: content,
	}
	var segments []Segment
	segmentsReady := false
	getSegments := func() []Segment {
		if !segmentsReady {
			segments = segmentDocument(content)
			segmentsReady = true
		}
		return segments
	}

	var tokensBySegment [][]Token
	tokensReady := false
	getTokensBySegment := func() [][]Token {
		if !tokensReady {
			currentSegments := getSegments()
			tokensBySegment = make([][]Token, len(currentSegments))
			for i := range currentSegments {
				tokensBySegment[i] = tokenizeSegment(content, currentSegments[i])
			}
			tokensReady = true
		}
		return tokensBySegment
	}

	analyzedReady := false
	analyzed := AnalyzedDocument{}
	getAnalyzed := func() AnalyzedDocument {
		if !analyzedReady {
			analyzed = AnalyzedDocument{
				Document:        doc,
				Segments:        getSegments(),
				TokensBySegment: getTokensBySegment(),
			}
			analyzedReady = true
		}
		return analyzed
	}

	findings := make([]Finding, 0)
	for _, compiledRule := range compiled {
		if compiledRule.checkDocument != nil {
			findings = appendWithRuleAttributes(findings, compiledRule, compiledRule.checkDocument(ctx, doc))
		}
		if compiledRule.checkSegment != nil {
			for _, segment := range getSegments() {
				findings = appendWithRuleAttributes(findings, compiledRule, compiledRule.checkSegment(ctx, segment))
			}
		}
		if compiledRule.checkTokens != nil {
			currentSegments := getSegments()
			currentTokensBySegment := getTokensBySegment()
			for i := range currentSegments {
				findings = appendWithRuleAttributes(findings, compiledRule, compiledRule.checkTokens(ctx, currentSegments[i], currentTokensBySegment[i]))
			}
		}
		if compiledRule.checkFlow != nil {
			findings = appendWithRuleAttributes(findings, compiledRule, compiledRule.checkFlow(ctx, getAnalyzed()))
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Position.Line != findings[j].Position.Line {
			return findings[i].Position.Line < findings[j].Position.Line
		}
		if findings[i].Position.Column != findings[j].Position.Column {
			return findings[i].Position.Column < findings[j].Position.Column
		}
		return findings[i].Message < findings[j].Message
	})

	return findings
}

func appendWithRuleAttributes(dst []Finding, compiledRule CompiledRule, src []Finding) []Finding {
	for i := range src {
		src[i].ID = compiledRule.ID
		src[i].Severity = compiledRule.Severity
	}
	return append(dst, src...)
}
