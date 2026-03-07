# No Suspicious Base64 Payload

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `no-suspicious-base64` |
| Default severity | `medium` |
| Summary | Detects long base64-like payloads |
| Description | Long inline base64 payloads can hide executable or exfiltration content from casual review. |

## What This Rule Does

This rule detects long base64-like payloads that look suspicious in context. It is aimed at opaque
encoded blobs that may be staging hidden data rather than short, harmless tokens.

## Why It's Important

Large base64 strings are easy to paste into prompts and hard to review by eye. They are often used
to conceal scripts, binaries, or exfiltration content until a later decode step.

## Why The Severity Is Rated Medium

The default severity is `medium` because base64 can be legitimate, especially in fixtures or test
data. The rule still matters because long opaque payloads are a common concealment technique.

## How The Rule Works Technically

Promptinel looks for tokens classified as base64, applies a minimum length threshold, and then runs
additional suspiciousness checks based on payload characteristics and surrounding context. Only
payloads that clear those heuristics produce findings.

## Recommendations For Handling Findings

Decode and inspect the payload before keeping it in the repository or prompt source. If it is
harmless test data, prefer shorter and clearer samples where possible, or isolate the blob in a
well-documented fixture.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
