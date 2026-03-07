# No Mixed Script Identifiers

[Back to overview](../Rules/Overview.md)

| Field            | Value                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Rule ID          | `no-mixed-script-identifiers`                                                                                                  |
| Default severity | `high`                                                                                                                         |
| Summary          | Detects mixed-script identifier and hostname spoofing                                                                          |
| Description      | Mixed-script identifiers and hostnames can hide homoglyph spoofing that impersonates trusted names in prompts and tool inputs. |

## What This Rule Does

This rule detects identifiers and hostnames that mix scripts such as Latin, Cyrillic, and Greek in
the same value. It applies both to normal identifier-like tokens and to URL hosts extracted from
URL tokens.

## Why It's Important

Mixed-script values are a common homoglyph-spoofing technique. They can make a malicious host,
filename, or identifier look visually similar to a trusted one while actually pointing somewhere
else.

## Why The Severity Is Rated High

The default severity is `high` because this technique directly attacks the trust a reviewer places
in visible names. If missed, it can redirect network access or file operations to attacker-chosen
targets.

## How The Rule Works Technically

Promptinel inspects URL hosts and identifier-like tokens and classifies their characters into
script groups. A finding is emitted when a value mixes scripts in a way that looks like a spoofing
attempt rather than a plain natural-language string.

## Recommendations For Handling Findings

Normalize the identifier or hostname to a single expected script, or replace it with a clearly
trusted value. If the mixed-script form is present only to demonstrate spoofing detection, label it
as such and keep it away from live instructions.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
