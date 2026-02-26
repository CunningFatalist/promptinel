# Release

## Purpose

The release flow is built around GoReleaser and GitHub Actions.

## Versioning

Promptinel embeds its version in `cmd.Version` at build time using linker flags. Release artifacts are expected to use
semantic versions with a leading `v`, such as `v1.2.3`. When the binary is built in development mode, the CLI prints
`development`. When a concrete version is set, the CLI prints that version with a `v` prefix if needed.

## Local Release Validation

Run `make setup` to start the development container, then run `make goreleaser-check` to validate `.goreleaser.yml` and
`make goreleaser-healthcheck` to verify the release environment. These checks run GoReleaser inside the `promptinel_app`
container so tool versions are consistent with the project Docker image.

## GitHub Release Workflow

The release workflow is defined in `.github/workflows/release.yml`. It runs on pushes to `main` and on tags that start
with `v`. On `main`, the workflow runs a GoReleaser snapshot build with publishing disabled to continuously verify
packaging. On version tags, the workflow runs a full GoReleaser release and publishes artifacts through the repository
`GITHUB_TOKEN`.

## GoReleaser Configuration

The GoReleaser configuration is in `.goreleaser.yml`. It builds `./main.go` as `promptinel` for Linux, macOS, and
Windows on both `amd64` and `arm64`. The build uses `CGO_ENABLED=0` and injects the resolved version into `cmd.Version`.
Archive output is `tar.gz` by default, with `zip` used for Windows.
