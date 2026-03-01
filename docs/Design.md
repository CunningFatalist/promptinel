# Promptinel Design

This document describes the product/design intent and how it maps to the current implementation.
For package-level technical detail, see [Architecture](./Architecture.md).

## Current State

### Product Principles

Promptinel is designed to be:

- deterministic and reproducible
- offline-first (no network dependency for detection)
- CI-friendly (stable ordering and machine-readable outputs)
- conservative in capability/trust assumptions

### Implemented Command Surface

- `scan`: static prompt security analysis with policy-based exit behavior
- `sanitize`: safe, explicit prompt normalization workflow
- `baseline create|update`: snapshot and incremental adoption support
- `rules list|describe`: discoverability for built-in rules

### Implemented Output Modes

`scan --output` currently supports:

- `text`
- `json`
- `sarif`

Design intent for output compatibility:

- text mode optimizes for operator readability in terminals and CI logs
- JSON mode provides a stable Promptinel schema with explicit schema versioning
- SARIF mode enables code-scanning/security tooling ingestion

### Trust and Environment Design

Detection behavior is context-aware by design:

- environment capability flags gate or adjust rule behavior
- trust levels (`trusted`, `untrusted`, `tainted`) tighten matching where needed

## Planned Roadmap

These are goals, not implementation guarantees:

- broaden flow-analysis coverage across more prompt attack patterns
- expose scanner worker limit tuning as a user-facing configuration
- expand machine-readable output options beyond `scan`

## Non-Goals

Promptinel does not aim to provide:

- runtime sandboxing or runtime monitoring
- probabilistic content moderation/classification
- guarantees of complete attack detection
