# No Multilayer Encoding

| Field            | Value                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Rule ID          | `no-multilayer-encoding`                                                                                                       |
| Default severity | `high`                                                                                                                         |
| Summary          | Detects multi-layer encoded payload staging                                                                                    |
| Description      | Combining URL encoding, base64-related content, and decode or decompress steps can hide executable payload staging in prompts. |

## What This Rule Does

This rule detects staged payloads that stack multiple encoding layers before a decode or
decompression step. It is meant to catch content that uses encoding depth to conceal what will
eventually be executed or unpacked.

## Why It's Important

Multi-layer encoding is a practical evasion technique because it makes payloads difficult to review
by eye and easy to transport through systems that only scan for obvious raw strings. It often shows
up in decode-then-execute workflows.

## Why The Severity Is Rated High

The default severity is `high` because the rule models a deliberate concealment pattern tied to
payload staging. That combination of obfuscation and likely execution materially raises the risk.

## How The Rule Works Technically

Promptinel performs flow analysis across nearby segments and builds evidence about URL encoding,
base64-like payloads, and decode or decompress stages. It reports a finding when those layers stack
closely enough to form a suspicious encoding pipeline.

## Recommendations For Handling Findings

Remove the encoded payload chain or replace it with reviewed, readable content. If you need an
encoding example for testing or teaching, reduce it to a clearly inert form and avoid pairing it
with decode or execution steps.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
