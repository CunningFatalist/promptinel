# Contributing

## Workflow

1. Fork the repository.
2. Create a branch from your fork using a Conventional Commits style branch name
   (for example: `feat/add-json-output`, `fix/handle-empty-input`).
3. Open a pull request from your fork.
4. Every pull request must close at least one issue (for example: `Closes #123`).

## Requirements

- Pull requests must have green pipelines.
- Commits must follow Conventional Commits.
- Pull request titles must follow Conventional Commits.
- Contributions must include tests for behavior changes and bug fixes.
- New or changed code must keep test coverage at 85% or higher. If coverage is lower, the pull request must explain why.
- When behavior changes, documentation updates are required.

## Local Checks

Run the same checks used by CI before opening a pull request:

```bash
make fmt fix vet vuln lint test
```

## Conventional Commits Examples

- `feat(scan): add json summary output`
- `fix(config): handle missing severity value`
- `docs(readme): clarify baseline command`
- `test(engine): add scan cancellation coverage`
