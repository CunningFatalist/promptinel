# No Bidi Control Characters

[Back to overview](./Overview.md)

| Field            | Value                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-bidi-control-characters`                                                                        |
| Default severity | `high`                                                                                              |
| Summary          | Detects bidirectional text control characters                                                       |
| Description      | Bidi control characters can visually reorder instructions and hide malicious intent in prompt text. |

## What This Rule Does

This rule scans the full document for Unicode bidirectional control characters such as RTL and
LTR overrides. It flags them anywhere they appear and adds extra signal when the character sits
inside a URL, path, or other identifier-like token.

## Why It's Important

Bidirectional controls can make text render differently from how it is stored. That makes prompt
reviews unreliable and lets attackers hide instructions, paths, or hostnames in plain sight.

## Why The Severity Is Rated High

The default severity is `high` because this is an obfuscation technique that directly undermines
human review. A miss can hide instructions that lead to execution, exfiltration, or trust-boundary
spoofing.

## How The Rule Works Technically

Promptinel walks the normalized document rune by rune and checks each character against its bidi
control character helper set. For each match, it computes the finding position and inspects the
surrounding non-whitespace token to see whether the character is embedded in a URL or path-like
value.

## Recommendations For Handling Findings

Remove the bidi control characters unless there is a strong and documented need for them. If the
content must demonstrate the character for testing or education, isolate it clearly so it is not
confused with live instructions.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
