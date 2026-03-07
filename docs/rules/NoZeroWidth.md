# No Zero Width Characters

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `no-zero-width` |
| Default severity | `high` |
| Summary | Detects hidden zero-width Unicode characters |
| Description | Invisible zero-width characters can hide instructions and make reviews unreliable. |

## What This Rule Does

This rule detects zero-width and related invisible formatting characters anywhere in the document.
It is a broad hidden-character check intended to catch content that looks clean while carrying
invisible text structure.

## Why It's Important

Invisible formatting characters make source review unreliable because they can change token
boundaries or hide meaningful content without leaving a visible trace. That is useful for
obfuscation and instruction smuggling.

## Why The Severity Is Rated High

The default severity is `high` because the pattern directly undermines human review and can hide
dangerous content in otherwise ordinary-looking text. A missed case can conceal instructions or
structural markers that affect downstream behavior.

## How The Rule Works Technically

Promptinel scans the normalized document rune by rune and checks each character against its
invisible-formatting helper set. For every match, it computes the exact source position and reports
the character class and name when that extra detail is available.

## Recommendations For Handling Findings

Remove the invisible character unless there is a very specific, documented reason to keep it. If it
must remain for a test case, make the case explicit and ensure reviewers know the content is
deliberately carrying hidden characters.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
