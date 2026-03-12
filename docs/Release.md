# Release

Promptinel releases are built around GoReleaser and GitHub Actions.

## What The Release Flow Does

The release workflow has two jobs:

- continuously validate packaging on the main branch
- publish release artifacts when a version tag is pushed

The workflow definition lives in `.github/workflows/release.yml`, and the packaging
configuration lives in `.goreleaser.yml`.

## Local Validation

To validate release configuration locally, start the development environment and run the
GoReleaser checks from there:

```bash
make setup
make goreleaser-check
make goreleaser-healthcheck
```

## Release Behavior

Main-branch runs perform a snapshot-style verification so packaging problems are caught early.
Tagged releases perform the real publication flow and publish artifacts through the repository
token available in GitHub Actions.

The build embeds the resolved version into `internal/version.BuildVersion` so
the CLI and library package can both report the version they were built with.
