# Contributing

If you are new to the repository, start with the [Onboarding Guide](./docs/Onboarding.md).

## Contribution Workflow

1. Fork the repository.
2. Create a branch with a Conventional Commits style name, such as
   `feat/add-json-output` or `fix/handle-empty-input`.
3. Open a pull request from your fork.
4. Link the pull request to the issue it resolves.

## Expectations

- pull requests should have green pipelines
- commits should follow Conventional Commits
- pull request titles should follow Conventional Commits
- behavior changes and bug fixes should include tests
- new or changed code should keep coverage at or above the project target, or explain the gap
- behavior changes should update documentation in the same change

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
