# 🛡️Promptinel

[![CI](https://github.com/CunningFatalist/promptinel/actions/workflows/ci.yml/badge.svg)](https://github.com/CunningFatalist/promptinel/actions/workflows/ci.yml)

**Promptinel** is a deterministic security scanner for machine-interpreted natural language.

It statically analyzes prompts *before an LLM or agent executes them* and detects instructions that could cause
unintended external actions — such as data exfiltration, tool misuse, or environment manipulation.

Promptinel treats prompts as executable artifacts.

---

## State

Promptinel is in early development and many features are still missing.

---

## Installation

_TODO_

---

## Usage

### Print version

```bash
promptinel --version
```

### Scan prompts

```bash
# Scan all files in the prompts/ directory with default rules
promptinel scan prompts/

# Scan with a custom config file
promptinel scan --config .promptinel.yaml prompts/

# Scan only Markdown files
promptinel scan --include "*.md" prompts/

# Scan all files except YAML files
promptinel scan --exclude "*.yaml" prompts/
```

### Sanitize prompts

This command is restricted to safe transformations, e.g. removing invisible characters etc.

```bash
# Preview transformations without applying them
promptinel sanitize prompts/

# Apply transformations to all files in the prompts/ directory
promptinel sanitize --apply prompts/

# Use a custom config file for sanitization
promptinel sanitize --config .promptinel.yaml --apply prompts/

# Only apply transformations to Markdown files
promptinel sanitize --include "*.md" --apply prompts/

# Apply transformations to all files except YAML files
promptinel sanitize --exclude "*.yaml" --apply prompts/
```

### Viewing and explaining rules

```bash
# List all available rules
promptinel rules list

# Explain the no-shell-commands rule
promptinel rules describe no-shell-commands
```

### Baseline (for CI adoption)

```bash
# Create a baseline file with current findings (e.g. to ignore existing issues in CI)
promptinel baseline create

# Update the baseline file with new findings (e.g. after fixing some issues)
promptinel baseline update
```

---

## Exit codes

| Code | Meaning                            |
|------|------------------------------------|
| 0    | no violations                      |
| 1    | violations below failure threshold |
| 2    | policy failure                     |

---

## Configuration

### Configuration File

Promptinel uses a `.promptinel.yaml` file for configuration. Here is an example:

```yaml
policy:
  fail-on: high
  warn-on: medium
  ignore-on: low

environment:
  can_execute_shell: true
  can_access_filesystem: true
  can_access_network: true
  has_secrets: true

trust:
  local-files: trusted
  remote-includes: untrusted
  user-input-placeholders: tainted

scopes:
  - path: agents/**
    severity: high

  - path: skills/**
    severity: high

  - path: prompts/**
    severity: medium

  - path: docs/**
    severity: low

rules:
  - id: no-zero-width
    enabled: true

  - id: no-instruction-override
    severity: high

  - id: no-shell-commands
    severity: high

  - id: no-secret-exfiltration
    severity: high

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

### Severity Levels

Severity levels are `low`, `medium`, and `high`. They apply
whenever you can define a threshold for a rule, e.g. in the policy section below.

### Policy

Your policy settings define enforcement behavior.

```yaml
policy:
  fail-on: high
  warn-on: medium
  ignore-on: low
```

### Environment (Agent Capabilities)

Risk depends on what the agent can do. The same prompt may be safe or critical 
depending on your environment.

**Promptinel assumes maximum capability unless configured otherwise.**

By default, Promptinel assumes your agent can run system commands, access your 
file system, and make outbound network requests. Promptinel also assumes your 
runtime environment has sensitive data available and that the agent could retrieve it. 

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
  – Fully controlled by you. No automatic severity escalation.
2. `untrusted` 
  – External but static content. Findings may be escalated.
3. `tainted` 
  – Dynamically influenced input (e.g. user data). Findings are treated conservatively.

This matters, because LLMs cannot reliably distinguish between instructions and data.
If user- (or otherwise externally) controlled content is embedded into a prompt template, 
it may override instructions or introduce hidden behavior. Trust boundaries allow Promptinel
to escalate findings.

```yaml
trust:
  local-files: trusted
  remote-includes: untrusted
  user-input-placeholders: tainted
```

### Scopes

Adjust severity based on location.

```yaml
scopes:
  - path: agents/**
    severity: high

  - path: docs/**
    severity: low
```

### Built-in Rules

```yaml
rules:
  - id: no-zero-width
    enabled: true

  - id: no-unsafe-templates
    severity: medium
```

Regex rules for simple constraints.

```yaml
custom-rules:
  - id: forbidden-host
    pattern: "evilcorp\\.com"
    severity: high
    message: "Disallowed external domain"
```

---

## Output Example

```
File: agents/build.md

Capabilities detected:
 - requests secrets
 - attempts instruction override
 - invokes shell commands

Risk: HIGH
Policy: FAIL
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

