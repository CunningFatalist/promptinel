# Promptinel

[![CI](https://github.com/CunningFatalist/promptinel/actions/workflows/ci.yml/badge.svg)](https://github.com/CunningFatalist/promptinel/actions/workflows/ci.yml)
![GitHub Release](https://img.shields.io/github/v/release/CunningFatalist/promptinel)

**Promptinel** is a deterministic security scanner for machine-interpreted natural language.

<p align="center">
  <img width="320" 
       src="./docs/image/logo.png" 
       alt='The Promptinel logo is a shield consisting of paper with placeholder texts representing prompts.' 
  />
</p>

It statically analyzes prompts *before an LLM or agent executes them* and detects instructions that could cause
unintended external actions, such as data exfiltration, tool misuse, or environment manipulation.

Promptinel treats prompts as executable artifacts.

`scan` processes files concurrently with deterministic output ordering to keep CI results stable.

---

## State

Promptinel is in early development and many features are still missing.

---

## Installation

### With Go

```bash
go install github.com/CunningFatalist/promptinel@latest
```

The `promptinel` binary will be installed into your `GOBIN` (or `$(go env GOPATH)/bin`).

### As Docker Command

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  golang:1.26.0 \
  sh -lc 'set -eu; GOBIN=/tmp/bin /usr/local/go/bin/go install github.com/CunningFatalist/promptinel@latest && /tmp/bin/promptinel scan .'
```

### As Docker Service

Minimal Compose + Dockerfile (recommended)

Create `Dockerfile.promptinel`:

```dockerfile
FROM golang:1.26.0

ARG PROMPTINEL_VERSION=vX.Y.Z

RUN GOBIN=/usr/local/bin go install github.com/CunningFatalist/promptinel@${PROMPTINEL_VERSION}

WORKDIR /work
ENTRYPOINT ["promptinel"]
```

Create `docker-compose.promptinel.yml`:

```yaml
services:
  promptinel:
    build:
      context: .
      dockerfile: Dockerfile.promptinel
      args:
        PROMPTINEL_VERSION: vX.Y.Z
    working_dir: /work
    volumes:
      - ./:/work
    command: ["scan", "."]
```

Build and run:

```bash
docker compose -f docker-compose.promptinel.yml build

docker compose -f docker-compose.promptinel.yml run --rm promptinel
```

### Build from Source

```bash
# Start the development container first (once per environment)
make setup

# Build inside the development container (required for release version metadata)
export BUILD_VERSION=x.x.x && make build
```

`BUILD_VERSION` is required for `make build`; the binary is written to `build/promptinel`.

---

## Usage

### Print Version

```bash
promptinel --version
```

### Scan Prompts

```bash
# Scan all files in the prompts/ directory with default rules
promptinel scan prompts/

# Scan with a custom config file
promptinel scan --config .promptinel.yaml prompts/

# Scan with built-in defaults only (do not auto-discover .promptinel.yaml)
promptinel scan --no-config-discovery prompts/

# Scan only Markdown files
promptinel scan --include "*.md" prompts/

# Scan all files except YAML files
promptinel scan --exclude "*.yaml" prompts/

# Emit structured JSON output (for CI parsers)
promptinel scan --output json prompts/

# Emit SARIF output (for GitHub/code-scanning ingestion)
promptinel scan --output sarif prompts/ > promptinel.sarif
```

### Sanitize Prompts

This command is restricted to safe transformations, for example removing invisible characters.

```bash
# Preview transformations without applying them
promptinel sanitize prompts/

# Apply transformations to all files in the prompts/ directory
promptinel sanitize --apply prompts/

# Use a custom config file for sanitization
promptinel sanitize --config .promptinel.yaml --apply prompts/

# Sanitize with built-in defaults only (do not auto-discover .promptinel.yaml)
promptinel sanitize --no-config-discovery --apply prompts/

# Only apply transformations to Markdown files
promptinel sanitize --include "*.md" --apply prompts/

# Apply transformations to all files except YAML files
promptinel sanitize --exclude "*.yaml" --apply prompts/
```

### Viewing and Explaining Rules

```bash
# List all available rules
promptinel rules list

# Explain the no-unsafe-templates rule
promptinel rules describe no-unsafe-templates
```

### Baseline for CI Adoption

```bash
# Create a baseline file with current findings (e.g. to ignore existing issues in CI)
promptinel baseline create

# Update the baseline file with new findings (e.g. after fixing some issues)
promptinel baseline update

# Scan while suppressing accepted findings from a baseline snapshot
promptinel scan --baseline .promptinel-baseline.json prompts/
```

`baseline create` and `baseline update` write `.promptinel-baseline.json` by default.  
Use `--file` to select a different baseline path.

Baseline snapshots are generated from raw scan findings (before `policy.warn-on` filtering), so accepted low-severity
findings can still be tracked and suppressed consistently in CI.

### Globbing

Promptinel uses glob patterns for:

- `scan --include`
- `scan --exclude`
- `baseline create --include`
- `baseline create --exclude`
- `baseline update --include`
- `baseline update --exclude`
- `sanitize --include`
- `sanitize --exclude`
- `filters.include[]` in `.promptinel.yaml`
- `filters.exclude[]` in `.promptinel.yaml`
- `scopes[].path` in `.promptinel.yaml`

#### Supported Pattern Behavior

- `*` matches any sequence of characters inside one path segment
- `?` matches exactly one character inside one path segment
- `[abc]` matches one character from a set
- `**` matches recursively across directory boundaries

#### Examples

```text
*.md            # Markdown files by basename
docs/*.md       # Markdown files directly under docs/
docs/**         # All files under docs/ recursively
agents/**/prod* # Any file/dir starting with "prod" at any depth under agents/
```

#### Practical Guidance

- Prefer anchored patterns like `docs/**` over broad top-level patterns such as `**/*.md`.
- Keep include/exclude lists focused and specific in large repositories.
- Use `**` only when recursive matching is needed; prefer `*` for single-segment matches.

---

## Exit Codes

| Code | Meaning                            |
|------|------------------------------------|
| 0    | no reportable policy violations    |
| 1    | warning threshold reached          |
| 2    | failure threshold reached          |

Code `0` can still occur when findings are filtered by `policy.warn-on` or suppressed by a baseline snapshot.

---

## Configuration

### Configuration File

Promptinel uses a `.promptinel.yaml` file for configuration. Here is an example:

```yaml
policy:
  fail-on: high
  warn-on: medium

environment:
  can_execute_shell: true
  can_access_filesystem: true
  can_access_network: true
  has_secrets: true

trust:
  local-files: trusted
  remote-includes: untrusted
  user-input-placeholders: tainted

limits:
  max_file_size_bytes: 5242880

filters:
  include:
    - "*.md"
  exclude:
    - "*.yaml"

scopes:
  - path: agents/**
    severity: high
    rules:
      - id: no-bidi-control-characters
        severity: high

  - path: skills/**
    severity: high

  - path: prompts/**
    severity: medium

  - path: docs/**
    severity: low
    rules:
      - id: no-unsafe-templates
        enabled: false
      - id: no-bidi-control-characters
        severity: medium

rules:
  - id: no-bidi-control-characters
    severity: high

  - id: no-command-chaining
    severity: medium

  - id: no-curl-pipe-shell
    severity: high

  - id: no-data-uri-payloads
    severity: medium

  - id: no-download-execute
    severity: medium

  - id: no-hidden-html-instructions
    severity: medium

  - id: no-insecure-http
    severity: low

  - id: no-metadata-service-access
    severity: high

  - id: no-override-capability-flow
    severity: high

  - id: no-prompt-injection-override
    severity: medium

  - id: no-secret-exfiltration-intent
    severity: high

  - id: no-secret-to-network-flow
    severity: high

  - id: no-sensitive-file-paths
    severity: high

  - id: no-staged-download-execution
    severity: high

  - id: no-suspicious-base64
    severity: medium

  - id: no-zero-width
    enabled: true

  - id: no-unsafe-templates
    severity: medium

custom-rules:
  - id: forbidden-domain-evilcorp
    pattern: "evilcorp\\.com"
    severity: high
    message: "Disallowed external domain referenced in prompt"

  - id: base64-payload-detection
    pattern: "[A-Za-z0-9+/]{40,}={0,2}"
    severity: medium
    message: "Suspicious base64-like payload detected"

  - id: curl-or-wget-usage
    pattern: "\\b(curl|wget)\\b"
    severity: high
    message: "Network download command detected in prompt"
```

If `--config` is not set, Promptinel auto-discovers `.promptinel.yaml` from the current directory and `$HOME`.
Use `--no-config-discovery` on `scan`, `sanitize`, `baseline create`, and `baseline update` to force secure defaults
unless you explicitly pass `--config`.

### Filters

Use filters to define default file selection globs in `.promptinel.yaml`:

```yaml
filters:
  include:
    - "*.md"
  exclude:
    - "*.yaml"
```

CLI flags take precedence over config values:

- `--include` overrides `filters.include`
- `--exclude` overrides `filters.exclude`

### Severity Levels

Severity levels are `low`, `medium`, and `high`. They apply
whenever you can define a threshold for a rule, e.g. in the policy section below.

### Policy

Your policy settings define enforcement behavior.

```yaml
policy:
  fail-on: high
  warn-on: medium
```

`fail-on` must be greater than or equal to `warn-on`.

`warn-on` acts as the minimum severity for policy findings shown in `Findings` and
used for `WARN`/`FAIL` exit outcomes.

Oversized-file skips (`scan-file-too-large`) are always printed in a separate
`Oversized Skips` section and remain informational-only (they do not affect exit code).

Baseline snapshots are built from raw findings before `warn-on` filtering.

### Environment

Risk depends on what the agent can do. The same prompt may be safe or critical
depending on your environment.

**Promptinel assumes maximum capability unless configured otherwise.**

By default, Promptinel assumes your agent can run system commands, access your
file system, and make outbound network requests. Promptinel also assumes your
runtime environment has sensitive data available and that the agent could retrieve it.

> [!TIP]
> The environment setting defines in which environment the scanned prompts will be consumed.
> It does not define Promptinel's own runtime environment.

```yaml
environment:
  can_execute_shell: true
  can_access_filesystem: true
  can_access_network: true
  has_secrets: true
```

### Trust Model

The trust model defines how Promptinel treats different input sources during analysis.
There are three levels:

1. `trusted`
   – Fully controlled by you. Base matching behavior applies.
2. `untrusted`
   – External but static content. Some rules use stricter matching.
3. `tainted`
   – Dynamically influenced input (e.g. user data). Rules match conservatively.

This matters, because LLMs cannot reliably distinguish between instructions and data.
If user- (or otherwise externally) controlled content is embedded into a prompt template,
it may override instructions or introduce hidden behavior. Trust boundaries allow Promptinel
to apply stricter rule behavior where needed.

```yaml
trust:
  local-files: trusted
  remote-includes: untrusted
  user-input-placeholders: tainted
```

### Limits

Use limits to guard scanner resource usage.

```yaml
limits:
  max_file_size_bytes: 5242880 # 5 MiB
```

Files above the limit are skipped and always surfaced in scan output under
`Oversized Skips` so operators can see analysis blind spots in local runs and CI logs.

### Scopes

You may adjust severity and per-rule behavior based on location.
The `path` field uses the same glob semantics as the guide above.

```yaml
scopes:
  - path: agents/**
    severity: high

  - path: docs/**
    severity: low
    rules:
      - id: no-unsafe-templates
        enabled: false
      - id: no-bidi-control-characters
        severity: medium
```

Scope precedence is deterministic:

- all matching scopes are evaluated in declaration order
- later matching scopes override earlier ones (**Last-Match-Wins**)
- within a file: global `rules[]` defaults are resolved first, then scope `severity`, then `scopes[].rules[]` per-rule overrides

`Last-Match-Wins` applies to both:

- scope-level `severity`
- per-rule overrides in `scopes[].rules[]` for the same `id` (merged field-by-field for `enabled` and `severity`)

For per-rule overrides, only explicitly set fields in later scopes replace earlier values.
Example: a later scope that only sets `severity` keeps the previous `enabled` value unchanged.
To re-enable a previously disabled rule, set `enabled: true` explicitly in a later matching scope.

### Built-In Rules

Use `promptinel rules list` to see all available rules. You can enable or disable rules and adjust their severity.

```yaml
rules:
  - id: no-bidi-control-characters
    severity: high

  - id: no-command-chaining
    severity: medium

  - id: no-curl-pipe-shell
    severity: high

  - id: no-data-uri-payloads
    severity: medium

  - id: no-download-execute
    severity: medium

  - id: no-hidden-html-instructions
    severity: medium

  - id: no-insecure-http
    severity: low

  - id: no-metadata-service-access
    severity: high

  - id: no-override-capability-flow
    severity: high

  - id: no-prompt-injection-override
    severity: medium

  - id: no-secret-exfiltration-intent
    severity: high

  - id: no-secret-to-network-flow
    severity: high

  - id: no-sensitive-file-paths
    severity: high

  - id: no-staged-download-execution
    severity: high

  - id: no-suspicious-base64
    severity: medium

  - id: no-zero-width
    enabled: true

  - id: no-unsafe-templates
    severity: medium
```

### Custom Rules

Promptinel allows custom regex rules for simple constraints.

```yaml
custom-rules:
  - id: forbidden-host
    pattern: "evilcorp\\.com"
    severity: high
    message: "Disallowed external domain"
```

---

## Output Example

### Output Formats

`scan` supports three output formats via `--output`:

- `text` (default): human-readable report for local usage and CI logs
- `json`: machine-readable Promptinel schema for custom integrations
- `sarif`: SARIF 2.1.0 report for security/code-scanning platforms

JSON compatibility expectations:

- `schema_version` uses semantic versioning
- additive fields are backward-compatible within the same major version
- breaking schema changes require a major version bump

Deterministic ordering guarantees:

- findings are grouped and sorted by file path and rule ID
- line lists are deduplicated and sorted numerically
- SARIF rule descriptors are sorted by rule ID

### CI SARIF Validation

The CI pipeline validates SARIF output end-to-end by:

- running the real CLI command (`go run main.go scan --output sarif ...`) against a clean fixture set used only for CI SARIF upload validation
- verifying core SARIF fields (`version`, `$schema`, run/tool/result structure)
- uploading the generated `promptinel.sarif` file as a CI artifact
- uploading SARIF to GitHub Code Scanning when permissions are available

The e2e test fixtures that intentionally contain findings are kept separate from this CI upload fixture so code-scanning uploads do not create synthetic alerts.

### Text Mode (`--output text`)

```
Capabilities:
 - can_execute_shell: true
 - can_access_filesystem: true
 - can_access_network: true
 - has_secrets: true

File: agents/build.md
 - lines 12 [high] no-zero-width: Zero-width character detected
 - lines 18 [medium] no-unsafe-templates: Unsafe template expression detected

Oversized Skips: none

Summary:
 - findings: 2
 - policy: FAIL
```

---

## Design Goals and Non-Goals

Promptinel is designed to be deterministic, offline, reproducible, CI- and agent-friendly,
and to provide a simple, extensible configuration model. It is also designed with a focus
on minimal false positives, and to be conservative in its assumptions about the environment
and trust model.

Non-goals for Promptinel include runtime monitoring, LLM, moderation, content filtering,
or subjective safety assessments. It is not designed to be a comprehensive security solution,
but rather a simple, focused tool to catch common prompt-based attack vectors before they are
executed.

Promptinel assumes the LLM will faithfully execute instructions. Furthermore, no one can build
a perfect scanner that guarantees to catch all possible attack vectors. I highly recommend reading
any prompts you can download from the internet in `vim` or another text editor which will show
you "invisible" characters. Don't trust online sources. Don't trust Markdown readers. Don't trust LLMs.
You don't have to be paranoid, but you should be aware of the risks and take reasonable precautions.

Intended Promptinel use cases include pre-commit hooks, CI pipelines, prompt marketplaces,
and local development environments.

---

## Motivation

Supply chain security is a topic I ([link](https://stefan-bauer.online/about/)) got interested in some years
ago, and I've been following it loosely for a couple of years. Then, at the
[SymfonyOnline January 2026](https://live.symfony.com/2026-online-january/), I saw a talk by Nils Adermann,
the creator of Composer. He talked about supply chain security, recent incidents, and modern attack vectors.
One thing he mentioned was how much easier and more valuable it was to target developers (social engineering),
dev machines, and build pipelines (CI) than production environments.

Several things are worrying in this regard. First, AI has helped bad actors as a whole to prioritize
and scale attacks much better. At the same time, developers are increasingly using AI to generate code,
while understanding little about the security implications. Many just pull Markdown (or other
prompt-containing) files from the internet and feed them to LLMs with little to no review.
This is a huge attack surface, and it is only going to get worse.

So I started to investigate what tools exist. For my dotfile repository, I wanted a lightweight
CLI tool to scan my agent config directories for suspicious patterns every time I commit or
update my dotfiles on a machine. I found nothing that fit the bill, so I decided to build it myself.
However, I quickly realized that Promptinel should be far more than a quick-and-dirty personal tool.
It has the potential to save many systems, and thereby people, from bad actors.

And that's what Promptinel is: a simple, offline, deterministic, reproducible CLI tool to scan prompt files
for security issues before they are consumed by an LLM or agent.

Stay safe, and happy coding! ✌️

---

## How Promptinel Compares to Other Tools

Promptinel performs static analysis before a prompt ever reaches an LLM.

It enforces structure, policy, and quality at development time, not at runtime.

What this means in practice:

- runs in CI/CD
- deterministic, rule-based validation
- zero runtime latency
- fully free and open source
- designed to complement, not replace, runtime systems

Promptinel shifts governance left. It prevents flawed prompts from being deployed.
It can be combined with any runtime guardrail, firewall, or orchestration framework.

### How It Differs From Other Tools

- Guardrails AI: 
  runtime input/output validation and automatic repair; 
  operates after prompt execution and adds runtime overhead.
- LangChain middleware and runtime guardrails: 
  runtime orchestration and filtering inside execution chains; 
  focused on flow control and live validation, not CI linting.
- Rebuff and LLM firewalls: 
  runtime detection of prompt injection and adversarial inputs; 
  reactive mitigation rather than preventative authoring checks.
- LLM orchestration frameworks (for example LangChain and LlamaIndex): 
  composition frameworks for prompts, tools, and memory; 
  execution systems rather than governance scanners.

### Why They Do Not Directly Compete

Runtime tools primarily act during execution. 
Promptinel acts _before_ execution.

Runtime tools mitigate live abuse and runtime risk.
Promptinel tries to prevent flawed prompts from ever reaching runtime.

Promptinel is complementary infrastructure, not a competing runtime system.

---

## Image Credits

The logo was created with ChatGPT and refined with Nano Banana.

---

## Contributing to Promptinel

### General Conventions

This project follows [Conventional Commits](https://www.conventionalcommits.org) for commit messages and
pull request titles.

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

When opening issues or pull requests, use the available templates:

- [Issue templates](.github/ISSUE_TEMPLATE/)
- [Pull request template](.github/pull_request_template.md)

## Development Conventions

When implementing Cobra commands in `cmd/*`:

- use `Run` (not `RunE`) for command handlers
- keep core command logic in helper functions that return `error`
- call `util.ExitOnCommandError(...)` directly from `Run` (without `if err != nil`) to centralize process exits
- return `exitcode.Error` from helper logic when a command needs a specific non-zero exit code

### Testing Scope

- Tests in `cmd` packages must only cover command behavior
  (argument validation, flag handling, output, and exit behavior).
- Algorithmic or reusable logic must not be tested through `cmd`;
  it must live in `internal/...` packages and be tested there.
- Use the general test naming format `Test_PackageName_Functionality_OptionalModifier`
  (for example, `Test_Config_Validation` or `Test_Config_Validation_InvalidInput`).
- Use `cmd` test names in the format `Test_Cmd_CommandName_WhatItDoes` (for example,
  `Test_Cmd_RootCommand_PrintsReleaseVersion`).
