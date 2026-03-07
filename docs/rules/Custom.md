# Custom Rules

[Back to overview](../Rules/Overview.md)

Promptinel custom rules are configured in your Promptinel config file rather than compiled into the
built-in rule registry. Today they are regex-based rules defined under `custom-rules`.

| Field            | Value                                               |
| ---------------- | --------------------------------------------------- |
| Rule ID          | Config-defined                                      |
| Default severity | Config-defined                                      |
| Summary          | `Custom regex rule`                                 |
| Description      | `User-defined regex-based rule from configuration.` |

## What Custom Rules Do

Custom rules let you add repository-specific detections without changing Promptinel source code.
Each custom rule supplies an id, severity, regex pattern, and finding message in configuration.

## Why They Are Documented Separately

Built-in rules have stable, dedicated documentation pages because they ship with Promptinel.
Custom rules only exist when a specific config file defines them, so Promptinel cannot provide a
separate static markdown page for every possible custom rule id.

## How Custom Rules Work Technically

Promptinel compiles each configured custom rule into a token-based regex matcher at load time. The
pattern runs against token values and emits findings using the configured message and severity.

## How To Configure Custom Rules

Custom rules live under the `custom-rules` key in `.promptinel.yaml`. Each rule needs:

- an `id`
- a `pattern`
- a `severity`
- a `message`

This is the smallest useful example:

```yaml
custom-rules:
  - id: disallowed-domain
    pattern: "evilcorp\\.com"
    severity: high
    message: "Disallowed external domain referenced in prompt"
```

Promptinel validates custom rule ids for uniqueness, compiles the regex at config-load time, and
rejects invalid patterns before scanning starts.

## Example Configurations

### Block References To Known Bad Domains

This is useful when a team wants to reject prompts that mention domains associated with phishing,
staging systems, or explicitly banned vendors.

```yaml
custom-rules:
  - id: blocked-domain-reference
    pattern: "\\b(?:evilcorp\\.com|pastebin\\.example|dropbox-transfer\\.example)\\b"
    severity: high
    message: "Prompt references a blocked external domain"
```

### Flag Embedded Secrets Or API Tokens

This kind of rule is useful for catching secrets that are specific to your environment and not
covered by a general built-in pattern.

```yaml
custom-rules:
  - id: internal-api-token
    pattern: "\\bsk-internal-[A-Za-z0-9]{24,}\\b"
    severity: high
    message: "Possible internal API token detected in prompt content"
```

### Escalate Suspicious Download Commands

If your environment treats any download tooling inside prompt content as suspicious, a custom rule
can raise that concern even when the built-in rules do not yet capture the exact phrasing you care
about.

```yaml
custom-rules:
  - id: download-tooling-reference
    pattern: "\\b(curl|wget|Invoke-WebRequest|iwr)\\b"
    severity: medium
    message: "Prompt references network download tooling"
```

### Detect Organization-Specific Sensitive Paths

Built-in rules cover many common sensitive file targets. Custom rules are useful when your team has
internal paths, mount points, or filenames that should always trigger review.

```yaml
custom-rules:
  - id: internal-secrets-path
    pattern: "/srv/secrets/|/opt/company/credentials/|\\.internal-prod-env\\b"
    severity: high
    message: "Prompt references an organization-specific sensitive path"
```

### Combine Multiple Custom Rules In One Config

In practice you will usually define several narrow rules rather than one broad pattern.

```yaml
custom-rules:
  - id: blocked-domain-reference
    pattern: "\\b(?:evilcorp\\.com|pastebin\\.example)\\b"
    severity: high
    message: "Prompt references a blocked external domain"

  - id: internal-api-token
    pattern: "\\bsk-internal-[A-Za-z0-9]{24,}\\b"
    severity: high
    message: "Possible internal API token detected in prompt content"

  - id: download-tooling-reference
    pattern: "\\b(curl|wget|Invoke-WebRequest|iwr)\\b"
    severity: medium
    message: "Prompt references network download tooling"
```

## Recommendations For Handling Findings

Keep custom rule ids descriptive and document the intent of each regex alongside the config that
declares it. Prefer narrow patterns with clear review guidance so findings remain actionable.

Start with patterns that are easy to explain to another reviewer. If a regex needs heavy escaping,
large alternation sets, or nuanced exceptions, add a short comment in your config describing what
the rule is trying to catch and what kinds of false positives are acceptable.
