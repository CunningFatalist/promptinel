# Documentation Index

Use this directory when the main readme file is no longer enough,
and you need the reasoning behind current behavior.

## Where To Start

If you are new to the project:

1. read the main [README](../README.md)
2. read [Onboarding](./Onboarding.md)
3. use the documents below based on the change you want to make

## By Topic

- [Architecture](./Architecture.md): package boundaries and the main runtime model
- [Design](./Design.md): product intent, tradeoffs, and non-goals
- [Library API](./Library.md): how to use Promptinel as an in-memory Go library
- [Configuration And Precedence](./Config.md): config loading, overrides, and scope behavior
- [Scan Pipeline](./ScanPipeline.md): how scan and baseline processing flow through the system
- [Severity Handling](./Severity.md): where severity comes from and how it affects output
- [Trust Processing](./Trust.md): how trust changes rule behavior
- [Rule Architecture](./Rules.md): rule phases, registry behavior, and authoring guidance
- [Release](./Release.md): release workflow and packaging

## Rule Reference

- [Rule Documentation Overview](./rules/Overview.md): built-in rule catalog
- [Custom Rules](./rules/Custom.md): how config-defined regex rules fit into the model
- [`docs/rules/`](./rules/): per-rule documentation for built-in rules
- [Rule Architecture](./Rules.md): where rule phases, authoring guidance, and the shared prompt
  corpus workflow are documented
