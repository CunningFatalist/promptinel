# No Role Header Spoofing

[Back to overview](../Rules/Overview.md)

| Field            | Value                                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Rule ID          | `no-role-header-spoofing`                                                                                                |
| Default severity | `high`                                                                                                                   |
| Summary          | Detects structured role-header spoof patterns                                                                            |
| Description      | Role header prefixes such as SYSTEM: or DEVELOPER: can be used to spoof higher-priority instruction channels in prompts. |

## What This Rule Does

This rule detects structured role-header prefixes embedded in prompt content. It targets lines that
try to look like higher-priority system, developer, or similar control channels.

## Why It's Important

Role-header spoofing is a direct attempt to smuggle authority into content that should not have it.
If the reader or downstream system treats the spoofed header as meaningful, the attack can reshape
subsequent behavior.

## Why The Severity Is Rated High

The default severity is `high` because the pattern is an explicit trust-boundary attack. It is not
just suspicious wording; it is an attempt to impersonate privileged instruction sources.

## How The Rule Works Technically

Promptinel scans each structural segment with a role-header pattern and reports the first match.
The detector is intentionally simple and focused on recognizable structured prefixes rather than
trying to understand the full semantics of the surrounding text.

## Recommendations For Handling Findings

Remove spoofed role headers from ordinary content and keep real role metadata in the actual system
that carries it. If the string is present for documentation or testing, make the example clearly
non-actionable and context-labeled.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
