# No Nonstandard Whitespace

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-nonstandard-whitespace`                                                                                                             |
| Default severity | `medium`                                                                                                                                |
| Summary          | Detects uncommon whitespace near actionable prompt content                                                                              |
| Description      | Uncommon whitespace can hide or break up dangerous instructions in prompts, especially around command, exfiltration, and override text. |

## What This Rule Does

This rule detects nonstandard whitespace characters when they appear near actionable prompt
content. It is intentionally narrower than a blanket whitespace rule and focuses on cases where the
spacing may be used to disguise commands or control flow.

## Why It's Important

Uncommon whitespace can separate or hide dangerous text without looking suspicious to a reader. In
security-sensitive prompts, that makes it a useful obfuscation tool for instructions, commands, and
transfer actions.

## Why The Severity Is Rated Medium

The default severity is `medium` because nonstandard whitespace is suspicious but can appear in
legitimate copied or multilingual text. The rule raises the signal only when the surrounding window
already looks actionable.

## How The Rule Works Technically

Promptinel scans the document rune by rune and identifies characters classified as nonstandard
whitespace. For each match, it checks a bounded context window around the character for actionable
signals before reporting the finding position.

## Recommendations For Handling Findings

Replace uncommon whitespace with ordinary spaces or explicit formatting that readers and tools can
review reliably. If the character is present for a safe reproduction case, document that purpose
clearly and keep the content isolated.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
