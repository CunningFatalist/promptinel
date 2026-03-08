# No Hidden Directionality

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                            |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-hidden-directionality`                                                                                                       |
| Default severity | `medium`                                                                                                                         |
| Summary          | Detects hidden RTL/LTR controls inside identifier-like tokens                                                                    |
| Description      | Directionality controls inside URLs, paths, and similar tokens can disguise the true rendered order of high-risk prompt content. |

## What This Rule Does

This rule detects bidi directionality markers only when they appear inside identifier-like values
such as URLs, paths, and similar tokens. It is narrower than the general bidi rule and focuses on
cases where the hidden marker changes the apparent meaning of an actionable token.

## Why It's Important

Directionality markers inside identifiers are especially dangerous because they can make a host,
file path, or command fragment look trustworthy while actually containing different underlying
content. That is a practical spoofing and review-evasion technique.

## Why The Severity Is Rated Medium

The default severity is `medium` because the rule is narrowly targeted at suspicious contexts, but
the marker itself may still appear in legitimate multilingual material outside those contexts. The
restricted scope keeps the signal focused while still treating it seriously.

## How The Rule Works Technically

Promptinel scans the full document for Unicode bidi control characters. For each match, it extracts
the surrounding non-whitespace token and checks whether that token looks identifier-like before
reporting a finding at the character position.

## Recommendations For Handling Findings

Remove the hidden directionality marker from URLs, paths, and similar values. If the content is a
test case for spoofing detection, keep it clearly labeled and isolated so readers do not mistake it
for a safe identifier.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
