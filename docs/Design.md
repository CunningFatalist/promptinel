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

Each segment is tokenized into lexical units.

This is not NLP. It is deterministic lexical scanning.

Token types may include:

- Word
- Operator
- URL
- ShellOperator
- Placeholder
- Base64Like
- StringLiteral

```

type Token struct {
Value    string
Kind     TokenKind
Position Position
}

```

Tokenization enables:

- Accurate rule matching
- Reduced false positives
- Future taint propagation

---

# 5. Rule Engine

Rules are pure functions.

```

type Rule interface {
ID() string
DefaultSeverity() Severity
Apply(ctx RuleContext, segment Segment, tokens []Token) []Finding
}

```

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

# 6. Analysis Context

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

# 7. Severity Resolution

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

# 8. Findings

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

# 9. Reporting Layer

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

# 10. Baseline Support

Baseline stores accepted findings.

Responsibilities:

- Hash findings deterministically
- Store snapshot file
- Filter current findings against baseline
- Update baseline cleanly

Baseline must be stable across runs.

---

# 11. Sanitization Flow

Sanitize reuses:

- Normalization
- Segment detection

Sanitization must:

- Be explicitly safe
- Never interpret instructions
- Never modify semantic meaning
- Support dry-run mode

---

# 12. Future Extensions

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

Filesystem → Normalize → Segment → Tokenize → Evaluate Rules → Resolve Severity → Report

Each layer is pure, testable, and independent.

This ensures reproducibility, CI safety, and long-term extensibility.