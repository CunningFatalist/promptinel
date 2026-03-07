# No URL Encoded Command Payload

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `no-url-encoded-command-payload` |
| Default severity | `high` |
| Summary | Detects URL-encoded command payloads intended for execution |
| Description | URL-encoded shell operators and payload fragments can hide decode-then-execute instructions from naive review. |

## What This Rule Does

This rule detects URL-encoded command fragments when they appear together with decode or execution
signals. It is designed to catch payloads that stay hidden until they are decoded at runtime.

## Why It's Important

Encoding shell operators and payload fragments is a common way to bypass simple string checks and
make malicious content look less obvious. When the same segment also includes decode or execution
behavior, the risk rises sharply.

## Why The Severity Is Rated High

The default severity is `high` because the rule combines concealment with an apparent execution
path. This is more than a suspicious string; it is a likely decode-then-run pattern.

## How The Rule Works Technically

Promptinel scans each segment for URL-encoded operator patterns, then requires supporting signals
that indicate payload content plus either decode behavior or execution behavior. It reports the
first encoded operator position that satisfies the full condition.

## Recommendations For Handling Findings

Decode and review the content before keeping it anywhere near executable workflows. If the segment
is only a security test or example, keep the encoded payload inert and clearly explain its purpose.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
