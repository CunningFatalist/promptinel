# No Unsafe Templates

| Field            | Value                                                                                                                |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-unsafe-templates`                                                                                                |
| Default severity | `medium`                                                                                                             |
| Summary          | Detects risky template expressions with execution or exfiltration intent                                             |
| Description      | Template expressions that invoke command, environment, or network-related operations increase prompt execution risk. |

## What This Rule Does

This rule detects template expressions that contain risky execution, environment, or network
signals. It is a general template-safety rule for expressions that look capable of doing more than
plain interpolation.

## Why It's Important

Unsafe template expressions blur the line between rendering and execution. In prompt-driven
workflows, that can let untrusted or loosely reviewed template content trigger powerful operations.

## Why The Severity Is Rated Medium

The default severity is `medium` because template expressions are not always live code, and some
engines expose helper functions intentionally. Even so, risky capability signals inside templates
deserve careful review.

## How The Rule Works Technically

Promptinel evaluates only template segments for this rule. It tokenizes the inner template content
and checks whether the expression contains known unsafe signals related to command execution,
environment access, or network behavior.

## Recommendations For Handling Findings

Restrict templates to simple data rendering wherever possible. If a template genuinely needs helper
behavior, keep that behavior narrow, reviewed, and insulated from untrusted inputs.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
