# Promptinel Architecture

Promptinel is a deterministic, static scanner for prompt files. The codebase is organized to keep CLI concerns thin,
isolate scanning logic in `internal`, and make rule execution predictable and extensible.

## High-Level Architecture

At runtime, the CLI (`cmd/scan.go`) orchestrates configuration loading, rule compilation, scanning, reporting, and
exit-code resolution.

```mermaid
flowchart TD
    A["CLI command: promptinel scan"] --> B["config.Load"]
    B --> C["builtin.NewRegistry"]
    C --> D["registry.Compile(cfg)"]
    D --> E["engine.NewScanner"]
    E --> F["ScanPaths(paths, include, exclude)"]
    F --> G["rules.Evaluate(content)"]
    G --> H["findings"]
    H --> I["exitcode.Resolve(policy, findings)"]
```

The key separation is:

- `cmd`: user interface, flag parsing, command wiring
- `internal/config`: typed config model, defaults, validation
- `internal/engine`: file collection/filtering plus per-file rule execution
- `internal/rules`: rule contracts, compilation, multi-phase evaluation
- `internal/exitcode`: policy threshold mapping to process codes

## Engine Design

`internal/engine.Scanner` is intentionally small and deterministic:

- resolves input paths
- recursively collects files (deduplicated and canonicalized)
- applies include/exclude path filters
- reads file content
- evaluates compiled rules with contextual metadata (path, environment, trust)
- applies scope-based severity overrides from config
- returns file-qualified findings

Important design choices:

- Context cancellation is supported (`context.Context`) and checked during file iteration.
- Paths are matched both relative to working directory and to input roots to reduce surprises in scope matching.
- Engine logic avoids side effects beyond reading files, making behavior testable and reproducible.

## Rule System and Interfaces

The rule system is capability-based: a rule implements only the phases it needs.

Core interfaces in `internal/rules/rule.go`:

- `Rule`: metadata only (`Metadata() Metadata`)
- `DocumentRule`: whole-file checks (`CheckDocument`)
- `SegmentRule`: structural-segment checks (`CheckSegment`)
- `TokenRule`: lexical checks (`CheckTokens`)
- `FlowRule`: full analyzed-document checks (`CheckFlow`)

Compilation in `internal/rules/registry.go` binds configured severity and enabled-state into `CompiledRule` values. Each
compiled rule stores only the phase callbacks actually implemented by that rule.

This avoids no-op methods and keeps extension ergonomic: new rules can be narrowly scoped to one phase or span multiple
phases.

## Rule Evaluation Pipeline

`rules.Evaluate(...)` executes rules in deterministic phase order with lazy preparation:

```mermaid
flowchart TD
    A["DocumentView"] --> B["Document checks"]
    A --> C["segmentDocument (lazy)"]
    C --> D["Segment checks"]
    C --> E["tokenizeSegment (lazy)"]
    E --> F["Token checks"]
    C --> G["AnalyzedDocument (lazy)"]
    E --> G
    G --> H["Flow checks"]
    B --> I["Attach rule ID + severity"]
    D --> I
    F --> I
    H --> I
    I --> J["Stable sort of findings"]
```

Key decisions:

- Segments/tokens/analyzed document are built lazily so phases incur cost only when needed.
- Rule metadata is attached after callbacks, centralizing severity and ID assignment.
- Findings are stably sorted (`rule ID`, `line`, `column`, `message`) to guarantee deterministic output.

## Built-In and Custom Rules

Built-ins are composed in `internal/rules/builtin` and registered centrally (`builtin.NewRegistry`).

Current built-in examples:

- `no-zero-width` (document phase): detects hidden zero-width characters
- `no-unsafe-templates` (segment phase): detects risky signals in template expressions

Custom regex rules are compiled from config (`custom-rules`) into first-class rule implementations, validated for regex
correctness and duplicate IDs.

## Configuration and Policy Decisions

`internal/config` enforces strict invariants before scanning:

- severity and trust enum validation
- policy ordering (`fail-on >= warn-on`)
- scope glob validation
- uniqueness of built-in override IDs and custom-rule IDs

Defaults are security-oriented (high capability environment assumptions, conservative trust levels) so scanning remains
useful even without a config file.

## Exit Semantics

`internal/exitcode.Resolve` maps the highest finding severity against policy thresholds:

- `0`: no actionable findings
- `1`: warning threshold reached
- `2`: failure threshold reached

Commands return typed `exitcode.Error` values so process exit mapping stays centralized in `util.ExitOnCommandError`.

## Notable Tradeoffs and Next Steps

Current tradeoffs:

- Simplicity over maximum throughput: files are read fully in memory and processed sequentially.
- Deterministic lexical/template analysis over probabilistic/NLP behavior.
- Terminal-friendly text output over machine-readable reporting formats.

Natural next architecture steps:

- implement `sanitize` and `baseline` command internals (currently placeholders)
- add JSON/SARIF output modes
- expand flow-level rules for deeper cross-segment reasoning
- add scalability controls (parallel scanning, large-file guardrails)
