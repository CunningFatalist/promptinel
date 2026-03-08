# Rule Name

[Back to overview](./Overview.md)

Use a StudlyCase filename that matches the rule name, for example `NoCurlPipeShell.md`.

| Field            | Value                                                        |
| ---------------- | ------------------------------------------------------------ |
| Rule ID          | `rule-id`                                                    |
| Default severity | `high`                                                       |
| Summary          | Short summary from `promptinel rules list --description`     |
| Description      | Full description from `promptinel rules list --description`. |

## What This Rule Does

Explain what the rule detects in user-facing terms. Keep this focused on the behavior the scanner
is looking for rather than implementation details.

## Why It's Important

Explain the security, safety, or review risk created by the pattern. Describe why a team should
care when this rule fires.

## Why The Severity Is Rated High

Explain why the default severity is set to `high`, `medium`, or `low`. Tie the rating to impact,
confidence, attack realism, or expected review cost.

## How The Rule Works Technically

Describe the detection approach in implementation-aware terms. Mention whether the rule operates on
the whole document, individual segments, tokens, or flow analysis across segments.

## Recommendations For Handling Findings

Describe how to review and resolve findings from this rule. Include safer alternatives where
relevant.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
