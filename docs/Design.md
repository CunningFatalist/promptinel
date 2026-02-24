# Promptinel Architecture

This document describes the internal architecture of Promptinel.

Promptinel is a deterministic, static analysis engine for machine-interpreted
natural language. It is implemented in Go and exposed via a Cobra-based CLI.

The architecture is intentionally layered, pure, and reproducible.

---

# Design Principles

- Deterministic: identical input always produces identical output.
- Offline: no network calls, no LLM dependencies.
- Context-aware: findings depend on environment and trust model.
- Composable: rules are isolated, pure, and extensible.
- CI-friendly: stable output and predictable exit codes.

---

# High-Level Pipeline

Promptinel processes files in the following stages:

1. File Discovery
2. Normalization
3. Segmentation
4. Tokenization
5. Rule Evaluation
6. Severity Resolution
7. Reporting

Each stage is independent and testable.

---

# Package Structure

Suggested internal layout:

```

/cmd
root.go
scan.go
sanitize.go
rules.go
baseline.go

/internal
/engine
engine.go
/config
config.go
validation.go
/loader
filesystem.go
/normalize
normalize.go
/segment
segment.go
/token
tokenizer.go
types.go
/rules
registry.go
rule.go
builtin/
/analysis
severity.go
context.go
/report
reporter.go
formatter.go
/baseline
baseline.go

```

CLI code in `/cmd`.  
All logic lives under `/internal`.

---

# 1. File Discovery

Responsible for:

- Walking directories
- Applying include/exclude glob filters
- Scope matching
- Loading file contents

Output:

```

type Document struct {
Path     string
Content  []byte
Scope    Scope
Trust    TrustLevel
}

```

No analysis occurs here.

---

# 2. Normalization Layer

Purpose: canonicalize input before analysis.

Responsibilities:

- Normalize line endings
- Strip zero-width characters
- Normalize Unicode
- Detect suspicious invisible characters
- Optional safe sanitization transforms

Output:

```

type NormalizedDocument struct {
Document
Content string
}

```

This layer must be pure and deterministic.

---

# 3. Segmentation Layer

Prompts often mix formats. We do lightweight structural segmentation.

We do not parse natural language.  
We only detect structural zones.

Segments may include:

- Plain text
- Markdown code blocks
- Inline code
- YAML blocks
- Template placeholders
- HTML tags

```

type Segment struct {
Type     SegmentType
Content  string
Position Position
}

```

Segmentation enables context-aware rule execution.

---

# 4. Tokenization Layer

Each segment is tokenized into lexical units by a deterministic lexer in
`internal/lexer`.

The lexer:

- operates in a single pass over UTF-8 input
- preserves exact byte offsets for every token
- detects zero-width and control characters
- uses `github.com/rivo/uniseg` only for Unicode grapheme segmentation helpers

Semantic classification upgrades lexical tokens into categories like URL,
placeholder, path, shell command, base64, and markdown code block.

```
type Token struct {
	Value    string
	Type     lexer.TokenType
	Start    int
	End      int
	Position Position
}
```

Tokenization enables:

- Accurate rule matching
- Reduced false positives
- Future taint propagation

---

# 5. Analysis Levels and Phases

Promptinel evaluates rules in explicit analysis levels. This keeps evaluation
deterministic while allowing gradually deeper checks.

The levels are:

1. Document level
    - Whole-file checks across normalized content.
    - Examples: invisible character detection, coarse regex matching.
2. Segment level
    - Structural-zone checks on each segment.
    - Examples: code-block-specific or template-block-specific checks.
3. Token level
    - Lexical checks over tokenized segments.
    - Examples: shell operator patterns, URL command combinations.
4. Flow level (optional, future extension)
    - Intra-document propagation checks, e.g. placeholder origin tracking.
    - Enabled when richer context analysis is needed.
5. Policy level
    - Final severity and enforcement decision from context and findings.

Phase order is fixed:

File Discovery -> Normalization -> Segmentation -> Tokenization ->
Document Checks -> Segment Checks -> Token Checks -> Flow Checks ->
Severity Resolution -> Reporting

Each phase is pure, deterministic, and independently testable.

---

# 6. Rule Engine

Rules are pure functions.

```

type Rule interface {
Metadata() Metadata
}

type DocumentRule interface {
CheckDocument(ctx RuleContext, doc DocumentView) []Finding
}

type SegmentRule interface {
CheckSegment(ctx RuleContext, segment Segment) []Finding
}

type TokenRule interface {
CheckTokens(ctx RuleContext, segment Segment, tokens []Token) []Finding
}

type FlowRule interface {
CheckFlow(ctx RuleContext, doc AnalyzedDocument) []Finding
}

```

Rules can implement one or more phase interfaces.
The engine dispatches only the methods a rule supports.

This capability-based model avoids forcing every rule to implement no-op
methods while still supporting phase checks in a consistent pipeline.

Rules must:

- Be deterministic
- Have no side effects
- Not modify input
- Not depend on external state

Rule categories:

- Pattern rules (regex-backed)
- Structural rules
- Capability-aware rules
- Trust-escalating rules

Rules are registered in a central registry:

```

type Registry struct {
rules []Rule
}

```

---

# 7. Analysis Context

Every rule executes with contextual information:

```

type RuleContext struct {
Environment Environment
TrustLevel  TrustLevel
Scope       Scope
}

```

Context allows:

- Capability amplification
- Trust escalation
- Scope-based severity overrides

---

# 8. Severity Resolution

Final severity is computed dynamically.

Effective severity is derived from:

- Rule base severity
- Environment capabilities
- Trust model escalation
- Scope modifiers

Example conceptual model:

```

effective =
baseSeverity

* trustEscalation
* environmentAmplification
* scopeModifier

```

This prevents naive static severity assignments.

---

# 9. Findings

```

type Finding struct {
RuleID    string
Message   string
Severity  Severity
File      string
Position  Position
}

```

Findings must be stable and reproducible.

---

# 10. Reporting Layer

Responsibilities:

- Group findings by file
- Print capability summary
- Compute final policy outcome
- Produce exit code

Optional future formats:

- JSON
- SARIF
- Machine-readable output

Exit codes:

- 0: no violations
- 1: below failure threshold
- 2: policy failure

---

# 11. Baseline Support

Baseline stores accepted findings.

Responsibilities:

- Hash findings deterministically
- Store snapshot file
- Filter current findings against baseline
- Update baseline cleanly

Baseline must be stable across runs.

---

# 12. Sanitization Flow

Sanitize reuses:

- Normalization
- Segment detection

Sanitization must:

- Be explicitly safe
- Never interpret instructions
- Never modify semantic meaning
- Support dry-run mode

---

# 13. Future Extensions

The architecture allows:

- Taint propagation across placeholders
- Multi-file include graph analysis
- Template variable origin tracking
- Cross-segment reasoning
- Policy plugins
- Custom rule packages

---

# Non-Goals

- No NLP parsing
- No LLM-based scanning
- No probabilistic scoring
- No runtime monitoring

Promptinel is static analysis for prompt artifacts.

---

# Summary

Promptinel is structured as a deterministic static analysis engine:

Filesystem -> Normalize -> Segment -> Tokenize ->
Evaluate Document/Segment/Token/Flow Checks ->
Resolve Severity -> Report

Each layer is pure, testable, and independent.

This ensures reproducibility, CI safety, and long-term extensibility.
