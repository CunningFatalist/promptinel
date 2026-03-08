# No Sensitive File Paths

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-sensitive-file-paths`                                                                                               |
| Default severity | `high`                                                                                                                  |
| Summary          | Detects references to commonly targeted sensitive local files                                                           |
| Description      | Access to credential files, host secrets, or system identity files can indicate prompt-driven data exfiltration intent. |

## What This Rule Does

This rule detects references to sensitive local file paths when they appear with read, copy, or
other collection-oriented intent. It focuses on files that are commonly targeted for credentials,
host identity, and environment secrets.

## Why It's Important

Sensitive file paths are often the first step in prompt-driven secret theft. Calling out the path
reference early helps stop collection behavior before the content ever reaches a transfer stage.

## Why The Severity Is Rated High

The default severity is `high` because the rule targets high-value local secret sources. In a
filesystem-capable environment, access to these paths can quickly lead to credential exposure or
persistence.

## How The Rule Works Technically

Promptinel scans each segment when filesystem access is relevant, finds the first known sensitive
path snippet, and then checks the nearby content for read or persistence intent. It only reports a
finding when both the path and the intent are present.

## Recommendations For Handling Findings

Remove direct references to sensitive paths unless they are essential to a clearly defensive use
case. Prefer controlled test fixtures or redacted placeholders over real credential or identity
file paths in prompts and examples.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
