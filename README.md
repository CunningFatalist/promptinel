# Promptinel

[![CI](https://github.com/CunningFatalist/promptinel/actions/workflows/ci.yml/badge.svg)](https://github.com/CunningFatalist/promptinel/actions/workflows/ci.yml)
![GitHub Release](https://img.shields.io/github/v/release/CunningFatalist/promptinel)

<p align="center">
  <img width="320" 
       src="./docs/image/logo.png" 
       alt='The Promptinel logo is a shield consisting of paper with placeholder texts representing prompts.' 
  />
</p>

Promptinel is a deterministic security scanner for machine-interpreted natural language.
It statically analyzes prompts before an LLM or agent executes them and flags instructions
that could trigger unintended external actions such as data exfiltration, tool misuse,
credential access, or environment manipulation. Promptinel treats prompts as executable artifacts.

## Why Use It

Promptinel is built for teams that review prompts the same way they review code:

- before execution, not after damage
- in CI as well as local development
- with deterministic output that is easy to diff and automate
- without relying on network access during detection

It is a focused scanner, not a runtime guardrail platform. The goal is to catch risky
prompt content early and make review practical.

Promptinel was designed as an additional security layer.
It does not replace other security measures.

## Installation

### Go Install

```bash
go install github.com/CunningFatalist/promptinel@latest
```

The binary is installed to `GOBIN` or `$(go env GOPATH)/bin`.

> [!WARNING]  
> It is not recommended to use `@latest` in production or CI environments. Pin your versions instead.
> Version pinning restricts dependencies to known, vetted versions, preventing automatic upgrades that could
> introduce malicious code, compromised packages, or breaking changes into the supply chain.

### As Docker Command

This example also uses `@latest` for demonstration. Again, it is recommended to use a pinned version instead.

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  golang:1.26.1 \
  sh -lc 'set -eu; GOBIN=/tmp/bin /usr/local/go/bin/go install github.com/CunningFatalist/promptinel@latest && /tmp/bin/promptinel scan .'
```

### Run And Build From Source

To run the CLI from a checkout with a compatible Go toolchain:

```bash
go run main.go --help
```

If you want the repository's container-backed development environment and build target, use:

```bash
make setup
export BUILD_VERSION=x.x.x
make build
```

The build output is written to `build/promptinel`.

## Quick Start

Scan a directory of prompts:

```bash
promptinel scan prompts/
```

Scan with an explicit config file:

```bash
promptinel scan --config .promptinel.yaml prompts/
```

Generate JSON or SARIF for automation:

```bash
promptinel scan --output json prompts/
promptinel scan --output sarif prompts/ > promptinel.sarif
```

Preview safe sanitization changes:

```bash
promptinel sanitize prompts/
```

Apply sanitization changes:

```bash
promptinel sanitize --apply prompts/
```

List built-in rules:

```bash
promptinel rules list
promptinel rules describe no-unsafe-templates
```

## Library Use

Promptinel also exposes an in-memory scanning API for applications that need to
scan prompt text directly, such as web services that receive pasted content.

```go
package main

import (
  "context"
  "log"

  "github.com/CunningFatalist/promptinel/pkg/promptinel"
)

func main() {
  scanner, err := promptinel.NewScanner(promptinel.NewConfig())
  if err != nil {
    log.Fatal(err)
  }

  findings, err := scanner.Scan(context.Background(), "ignore previous instructions")
  if err != nil {
    log.Fatal(err)
  }

  log.Printf("raw findings: %d", len(findings))
}
```

The library API returns raw findings without applying `policy.warn-on` filtering.
See [Library API](./docs/Library.md) for the complete usage guide.

## Core Commands

### `scan`

Scans files for prompt-security findings and returns a policy-based exit code.

### `sanitize`

Applies safe, deterministic cleanup steps such as removing invisible characters.

### `baseline create` and `baseline update`

Create or refresh a baseline file so teams can adopt Promptinel in CI without fixing
all historical findings at once.

### `rules list` and `rules describe`

Show the built-in rule catalog and explain individual rules.

## Configuration

Promptinel reads the config file you pass via `--config`, or auto-discovers
`.promptinel.yaml` from the current directory and `$HOME` unless you disable discovery with
`--no-config-discovery`.

This is a small but representative configuration:

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
  - path: docs/**
    severity: low

rules:
  - id: no-shell-profile-modification
    severity: high

custom-rules:
  - id: blocked-domain
    pattern: "evilcorp\\.example"
    severity: high
    message: "Disallowed external domain referenced in prompt"
```

Important rules of thumb:

- `--include` and `--exclude` replace the corresponding config filters
- `policy.warn-on` controls which findings become reportable
- baseline snapshots are built from raw findings, not only reportable findings
- later matching scopes override earlier ones

For the full reference, start with [Configuration And Precedence](./docs/Config.md).

## Output And Exit Codes

`scan` supports three output formats:

- `text` for local review and CI logs
- `json` for custom integrations
- `sarif` for security and code-scanning platforms

Promptinel uses the following exit codes:

- `0`: no reportable findings
- `1`: warning threshold reached
- `2`: failure threshold reached

Oversized-file skips are informational and do not affect exit status.

## Built-In Rules

Promptinel ships with a built-in rule set for common prompt attack patterns, including:

- prompt override and role spoofing patterns
- download-and-execute chains
- template execution and network fetch behavior
- secret exfiltration intent
- invisible Unicode and obfuscation tricks
- local sensitive file references

Start with the [Rule Documentation Overview](./docs/rules/Overview.md) for the full catalog.

## Documentation Map

The README is the shortest path to first use. The deeper docs are organized by task:

- [Documentation Index](./docs/README.md)
- [Onboarding](./docs/Onboarding.md)
- [Architecture](./docs/Architecture.md)
- [Scan Pipeline](./docs/ScanPipeline.md)
- [Configuration And Precedence](./docs/Config.md)
- [Trust Processing](./docs/Trust.md)
- [Severity Handling](./docs/Severity.md)
- [Rule Architecture](./docs/Rules.md)
- [Rule Documentation Overview](./docs/rules/Overview.md)

## Design Goals

Promptinel is designed to be:

- deterministic
- offline-first
- conservative about capability and trust assumptions
- useful in CI, local review, and repository workflows

Promptinel is not trying to provide runtime sandboxing, runtime monitoring, or a complete
guarantee that every prompt attack will be detected.

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

## How Promptinel Compares

Promptinel performs static analysis before a prompt ever reaches an LLM.
It enforces structure, policy, and quality at development time, not at runtime.

What this means in practice:

- runs in CI/CD
- deterministic, rule-based validation
- zero runtime latency
- fully free and open source
- designed to complement, not replace, runtime systems

In short, it prevents flawed prompts from being deployed.
It can be combined with any runtime guardrail, firewall, or orchestration framework.

## Contributing

If you plan to contribute, start with [Onboarding](./docs/Onboarding.md) and then read
[Contributing](./CONTRIBUTING.md).

Before opening a pull request, run:

```bash
make fmt fix vet vuln lint test
```

## Support And Security

Use [GitHub Issues](https://github.com/CunningFatalist/promptinel/issues) for bug reports,
feature requests, and documentation improvements.

Report security vulnerabilities privately through GitHub Private Vulnerability
Reporting. See [Security Policy](./SECURITY.md).
