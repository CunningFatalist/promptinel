# ADR 20250307: Provenance-Aware Trust Analysis

## Status

Accepted

## Context

Promptinel exposes a trust model with three sources:

- `local-files`
- `remote-includes`
- `user-input-placeholders`

Today, scanner execution effectively collapses trust to a single document-level value. That means
mixed-trust documents are not modeled correctly. In particular, a trusted prompt template that
contains tainted placeholders is still evaluated as fully trusted.

## Decision

Promptinel will implement provenance-aware trust analysis.

The scanner will keep a base trust level for the document and overlay lower-trust spans for content
derived from sources such as user input placeholders and remote includes. Rules will evaluate the
effective trust of the specific region they inspect rather than relying on one file-wide trust
value.

Trust is monotonic: derived content may lower trust, but never raise it.

## Alternatives Considered

### 1. Document-Level Trust With Path-Based Overrides

Use only file-level trust and extend scopes to mark paths as trusted, untrusted, or tainted.

Pros:

- Small implementation change
- Fits the current scanner shape

Cons:

- Does not model mixed-trust documents
- Leaves placeholder and remote-include trust mostly declarative

### 2. Rule-Specific Trust Heuristics

Teach individual rules to treat placeholders or include-like constructs as lower trust without
changing core analysis.

Pros:

- Fastest path to improved detection
- Minimal engine changes

Cons:

- Trust semantics become inconsistent across rules
- Hard to maintain and easy to miss in new rules

### 3. Provenance-Aware Trust Spans

Represent trust as a base document level plus lower-trust spans derived from specific sources.

Pros:

- Correct for mixed-trust documents
- Centralizes trust semantics
- Scales to future trust-aware rules

Cons:

- Requires moderate engine and rule API changes

### 4. Full Prompt Provenance Graph

Build a richer intermediate representation for templates, includes, and interpolated content before
running rules.

Pros:

- Strongest long-term model
- Supports future cross-source flow analysis

Cons:

- Highest implementation complexity
- Larger redesign than currently needed

## Rationale

Alternative 3 is the smallest approach that correctly implements the advertised trust model.
Alternative 1 improves configuration ergonomics but not correctness. Alternative 2 creates
duplicated policy logic in rules. Alternative 4 is a plausible future direction, but it is too
large for the current gap.

## Consequences

Promptinel will need:

- trust ordering semantics (`trusted < untrusted < tainted`)
- trust spans or equivalent provenance metadata in analysis context
- rule helpers for region-level trust queries
- updated tests for mixed-trust documents
- updated documentation to describe actual enforced behavior
