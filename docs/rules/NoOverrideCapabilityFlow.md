# No Override Capability Flow

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `no-override-capability-flow` |
| Default severity | `high` |
| Summary | Detects prompt overrides combined with actionable capability signals |
| Description | When instruction-override phrases are combined with shell, network, or sensitive file operations, risk increases significantly. |

## What This Rule Does

This rule detects documents that combine instruction-override language with concrete capability
signals such as shell execution, network access, filesystem actions, secret handling, or
protocol-level tool behavior.

## Why It's Important

Override language alone is concerning, but the real danger is when it is paired with instructions
that can actually do something sensitive. That combination is a strong sign of prompt injection
designed to push a capable agent past its intended boundaries.

## Why The Severity Is Rated High

The default severity is `high` because the rule correlates override intent with real operational
capabilities. This is closer to an attack plan than to a weak heuristic.

## How The Rule Works Technically

Promptinel first finds the earliest override phrase in the document, then analyzes tokenized
content for network, shell, filesystem, secret, and protocol signals. It only raises a finding if
the matched capabilities are actually relevant in the current context.

## Recommendations For Handling Findings

Remove the override language, the capability instructions, or both. If the content is intentionally
demonstrating an attack pattern, make it unmistakably educational and keep it separate from live
automation inputs.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
