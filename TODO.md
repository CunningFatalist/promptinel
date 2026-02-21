# TODO

## Documentation and project setup

- [ ] Write the `Installation` section in `README.md` (currently `_TODO_`).
- [ ] Add a documented release process (versioning, build artifacts, and publish steps).
- [ ] Add a `CODE_OF_CONDUCT.md`.
- [ ] Add GitHub issue templates.
- [ ] Add a GitHub pull request template.
- [ ] Add usage tutorials/examples beyond command snippets (CI, pre-commit, and local workflows).

## CLI features promised in README but not implemented yet

- [ ] Implement `sanitize` command behavior (currently placeholder output only).
- [ ] Add `sanitize --apply` support.
- [ ] Add `sanitize --config` support.
- [ ] Add `sanitize --include` support.
- [ ] Add `sanitize --exclude` support.
- [ ] Implement `baseline create` subcommand.
- [ ] Implement `baseline update` subcommand.
- [ ] Integrate baseline filtering into scanning/policy evaluation flow.

## Core architecture gaps vs `docs/Design.md`

- [ ] Implement dedicated normalization layer/package (line endings, Unicode normalization, invisible-char handling).
- [ ] Implement dedicated segmentation layer/package (text/code/template structural zones).
- [ ] Implement dedicated tokenization layer/package (deterministic lexical token scanning).
- [ ] Add analysis context handling for trust and environment amplification in rule evaluation.
- [ ] Implement scope-based severity overrides during effective severity resolution.
- [ ] Add reporting layer improvements (grouped findings, capability summary, policy summary).
- [ ] Add machine-readable output formats (`JSON`, `SARIF`).
- [ ] Implement stable baseline snapshot hashing and deterministic baseline storage format.

## Rule coverage

- [ ] Add more built-in rules beyond `no-zero-width` and `no-unsafe-templates`.
- [ ] Add rule categories outlined in design (structural, capability-aware, trust-escalating rules).

## Future extensions from design (not started)

- [ ] Taint propagation across placeholders.
- [ ] Multi-file include graph analysis.
- [ ] Template variable origin tracking.
- [ ] Cross-segment reasoning.
- [ ] Policy plugins.
- [ ] Custom rule packages.
