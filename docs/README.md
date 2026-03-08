# Documentation Index

Use this directory as the reference set for Promptinel's current behavior.

## Start Here

- [Architecture](./Architecture.md): package boundaries, runtime model, and current roadmap
- [Configuration And Precedence](./Config.md): config loading, CLI overrides, and scope precedence
- [Scan Pipeline](./ScanPipeline.md): shared scan flow and scan-only post-processing
- [Severity Handling](./Severity.md): severity sources, filtering, and exit-code effects
- [Trust Processing](./Trust.md): trust levels, span overlays, and rule-facing trust helpers
- [Rule Architecture](./Rules.md): rule phases, registry behavior, and authoring guidance

## Audience Guide

- New contributors: start with [Onboarding](./Onboarding.md), then read this index top to bottom
- Users configuring the scanner: start with [Configuration And Precedence](./Config.md)
- Contributors changing detection behavior: read [Rule Architecture](./Rules.md),
  [Trust Processing](./Trust.md), and [Severity Handling](./Severity.md)
- Contributors debugging scan output: read [Scan Pipeline](./ScanPipeline.md) and
  [Architecture](./Architecture.md)

## Rule Reference

- [Rule Documentation Overview](./rules/Overview.md): built-in rule catalog
- [`docs/rules/`](./rules/): per-rule user-facing documentation
