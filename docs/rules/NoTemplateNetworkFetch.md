# No Template Network Fetch

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-template-network-fetch`                                                                                                        |
| Default severity | `medium`                                                                                                                           |
| Summary          | Detects dynamic network or tool fetch behavior in templates                                                                        |
| Description      | Template expressions that dynamically construct network fetches or tool invocations can turn untrusted data into external actions. |

## What This Rule Does

This rule detects template expressions that dynamically build network fetches or similar tool
invocations. It focuses on templates where the target or operand is data-driven rather than a fixed
literal value.

## Why It's Important

Templates often look declarative, but dynamic fetch behavior can turn them into action-generating
code. When untrusted data influences the target, the template becomes an execution boundary rather
than a static rendering step.

## Why The Severity Is Rated Medium

The default severity is `medium` because dynamic template fetches are suspicious but can appear in
legitimate automation. They still require review because they can convert untrusted data directly
into outbound actions.

## How The Rule Works Technically

Promptinel only evaluates this rule on template segments. It tokenizes the inner template content,
looks for fetch-related terms or URL signals, and then checks whether the surrounding operands are
dynamic rather than fixed safe literals.

## Recommendations For Handling Findings

Move network access out of templates when possible, or constrain templates to fixed reviewed
destinations. If dynamic behavior is required, validate the input strictly and keep the execution
surface explicit in code rather than hidden in template syntax.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
