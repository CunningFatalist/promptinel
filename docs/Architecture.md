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
- `internal/lexer`: deterministic lexical + semantic tokenization with byte offsets
- `internal/exitcode`: policy threshold mapping to process codes

## Engine Design

`internal/engine.Scanner` is intentionally small and deterministic:

- resolves input paths
- recursively collects files (deduplicated via canonical path keys while preserving cleaned scan paths)
- applies include/exclude path filters
- reads file content in a bounded worker pool
- evaluates compiled rules with contextual metadata (path, environment, trust) per worker
- applies scope-based severity overrides from config
- returns file-qualified findings in stable file order

Important design choices:

- Context cancellation is supported (`context.Context`) and checked during file iteration.
- Paths are matched both relative to working directory and to input roots to reduce surprises in scope matching.
- Concurrent scanning is bounded by `GOMAXPROCS` and preserves deterministic output ordering.
- Engine logic avoids side effects beyond reading files, making behavior testable and reproducible.

## Rule System and Interfaces

The rule system is capability-based: a rule implements only the phases it needs.

Core interfaces in `internal/rules/rule.go`:

- `Rule`: metadata only (`Metadata() Metadata`)
- `DocumentRule`: whole-file checks (`CheckDocument`)
- `SegmentRule`: structural-segment checks (`CheckSegment`)
- `TokenRule`: lexical checks (`CheckTokens`)
- `FlowRule`: full analyzed-document checks (`CheckFlow`)

`Token` values provided to `TokenRule` include:

- semantic `Type` (`lexer.TokenType`)
- `Value`
- byte `Start`/`End` offsets
- line/column `Position`

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
    C --> E["tokenizeSegment (lazy: lexer.Lex + lexer.Classify)"]
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

## Lexer Architecture

Tokenization is implemented in `internal/lexer` and is explicitly deterministic and offline:

- single-pass UTF-8 lexing (`lexer.Lex`) without global `[]rune` conversion
- exact byte offsets on every token
- explicit detection for zero-width and control characters
- semantic post-processing (`lexer.Classify`) for URLs, placeholders, base64-like values, shell commands, paths, and code blocks
- Unicode grapheme segmentation helper via `github.com/rivo/uniseg` (`Graphemes`)

The rules layer consumes these tokens; it does not perform raw-string lexical tokenization.

## Built-In and Custom Rules

Built-ins are composed in `internal/rules/builtin` and registered centrally (`builtin.NewRegistry`).

Current built-in examples:

- `no-zero-width` (token phase): detects zero-width tokens emitted by the lexer
- `no-unsafe-templates` (token phase over template segments): detects risky execution/exfiltration signals in template expressions

Custom regex rules are compiled from config (`custom-rules`) into first-class token-phase rule implementations,
validated for regex correctness and duplicate IDs. Regex matching is performed on `Token.Value` rather than on raw file
content.

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

- Files are read fully in memory per target file (simple and fast for typical prompt files).
- Deterministic lexical/template analysis over probabilistic/NLP behavior.
- Terminal-friendly text output over machine-readable reporting formats.

Natural next architecture steps:

- implement `sanitize` and `baseline` command internals (currently placeholders)
- add JSON/SARIF output modes
- expand flow-level rules for deeper cross-segment reasoning
- add large-file guardrails and configurable worker limits
