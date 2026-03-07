# No Secret Exfiltration Intent

[Back to overview](../Rules/Overview.md)

| Field            | Value                                                                                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-secret-exfiltration-intent`                                                                          |
| Default severity | `high`                                                                                                   |
| Summary          | Detects co-occurrence of secret targets and exfiltration actions                                         |
| Description      | Prompts that combine secret-related terms with transfer actions often indicate data exfiltration intent. |

## What This Rule Does

This rule detects segments where secret-related terms and exfiltration-oriented actions appear
close together. It is intended to catch prompts that talk about stealing, sending, copying, or
uploading sensitive material.

## Why It's Important

This is a strong intent signal for data theft. Even before a specific destination is named, the
combination of secret targets and transfer language often reveals what the prompt is trying to do.

## Why The Severity Is Rated High

The default severity is `high` because the rule correlates sensitive targets with outbound intent.
That is a meaningful attack signal, especially in environments that expose secrets to tools or
agents.

## How The Rule Works Technically

Promptinel tokenizes relevant segments when both secrets and network access are in scope. It tracks
secret-like tokens and exfiltration-like tokens, then reports a finding when the nearest pair falls
within a configured token window that is broader for untrusted content.

## Recommendations For Handling Findings

Treat the content as likely malicious unless it is clearly an explanation, test case, or defensive
analysis. Remove the transfer language, or rewrite the material so it discusses the pattern without
instructing an agent to act on secrets.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
