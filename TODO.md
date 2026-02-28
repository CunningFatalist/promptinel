# TODO

## Documentation and project setup

These items improve project onboarding, contributor consistency, and release reliability.

- [ ] Write the `Installation` section in `README.md` (currently `_TODO_`).
- [ ] Add a documented release process (versioning, build artifacts, and publish steps).
- [ ] Add a `CODE_OF_CONDUCT.md`.
- [ ] Add GitHub issue templates.
- [ ] Add a GitHub pull request template.
- [ ] Add usage tutorials/examples beyond command snippets (CI, pre-commit, and local workflows).

## Architecture remediation (from full architectural review on 2026-02-25)

These items address concrete architectural risks found in the full review and reduce security, operability, and
maintenance gaps.

### 1) Make rule evaluation truly context-aware (environment + trust)

This is needed because context values are currently passed through the pipeline but mostly not used by rules, which
weakens policy relevance.

- [ ] Define and document the expected behavior for `rules.Context` usage:
  environment-only effects, trust-only effects, and combined effects.
- [ ] Update built-in rules to consume `ctx Environment` and/or `ctx TrustLevel` where applicable
  instead of ignoring context parameters.
- [ ] Add focused tests proving findings change (or severity changes) based on:
  capability flags and trust levels.
- [ ] Update architecture docs so claims about context-aware detection match implementation.

### 2) Ensure oversized-file skips are always visible to operators

This is needed because skipped files can currently disappear from default output, creating silent analysis blind spots.

- [ ] Redesign oversized file handling so skip diagnostics are never silently dropped by
  `warn-on` severity filtering.
- [ ] Implement scanner/report changes so skipped files are always surfaced in scan output
  (and visible in CI logs).
- [ ] Add tests for default policy (`warn-on: medium`) proving oversized file skips are reported.
- [ ] Decide and document whether oversized files should affect exit code policy or remain informational only.

### 3) Improve cancellation propagation and responsiveness

This is needed to ensure long scans can stop quickly and predictably when users or CI systems cancel execution.

- [ ] Pass Cobra command context into scan execution (`cmd.Context()`) instead of using `context.Background()`.
- [ ] Update worker/job orchestration to stop scheduling quickly when context is canceled.
- [ ] Add tests that verify early cancellation behavior on larger input sets.
- [ ] Document cancellation guarantees and limitations in architecture docs.

### 4) Remove duplicated file discovery/filtering logic

This is needed to avoid behavioral drift between scan and sanitize, and to reduce long-term maintenance overhead.

- [ ] Extract shared file collection, deduplication, and include/exclude matching into a reusable internal package.
- [ ] Migrate both scan and sanitize paths to the shared implementation.
- [ ] Add regression tests that compare scan/sanitize file targeting behavior for the same patterns.
- [ ] Keep behavior deterministic and backward compatible unless explicitly documented as a breaking change.

### 5) Align architecture/design documentation with reality

This is needed because current docs mix implemented and planned states, which can mislead contributors and future
agents.

- [ ] Reconcile `docs/Design.md` and `docs/Architecture.md` with the actual package layout and implemented phases.
- [ ] Clearly mark sections as `current state` vs `planned/roadmap` to avoid ambiguity.
- [ ] Remove or relabel segment/package descriptions that are not implemented yet.
- [ ] Add a short changelog section for architecture doc updates.

### 6) Decouple policy/report/baseline layers from engine-specific types

This is needed to reduce cross-package coupling and make future scanner/reporting evolution easier.

- [ ] Introduce a shared finding model package that is not owned by `internal/engine`.
- [ ] Refactor `internal/exitcode`, `internal/report`, and `internal/baseline` to consume the shared model.
- [ ] Keep scan behavior and output stable while refactoring type boundaries.
- [ ] Add tests ensuring no behavioral regressions in exit code resolution, report grouping, and baseline filtering.

### 7) Add machine-readable output modes (JSON and SARIF)

This is needed to support CI integrations and security tooling pipelines that require structured scanner output.

- [ ] Add an `--output` flag for `scan` (e.g. `text`, `json`, `sarif`) with deterministic ordering guarantees.
- [ ] Implement JSON report rendering with a stable schema and documented versioning strategy.
- [ ] Implement SARIF report rendering suitable for GitHub/code-scanning ingestion.
- [ ] Add tests that validate schema shape, deterministic ordering, and parity with text-mode findings.
- [ ] Document output format semantics and compatibility expectations in `README.md` and architecture docs.

### Suggested implementation order

This order prioritizes highest-risk security and visibility fixes first, then operability, then structural cleanup.

- [ ] Phase A: context-aware rules + oversized-file visibility (items 1 and 2; highest risk reduction).
- [ ] Phase B: cancellation + discovery deduplication cleanup (items 3 and 4; operability/maintainability).
- [ ] Phase C: model decoupling + documentation alignment (items 6 and 5; long-term evolution).
