# No Transcript Injection

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-transcript-injection`                                                                                                                   |
| Default severity | `high`                                                                                                                                      |
| Summary          | Detects transcript-style role alternation used for instruction smuggling                                                                    |
| Description      | Fake multi-role transcripts embedded in prompt content can smuggle instructions across role boundaries and should be treated as suspicious. |

## What This Rule Does

This rule detects content that imitates a multi-role transcript, such as alternating system, user,
or assistant lines. It focuses on sequences that look long enough and suspicious enough to be used
for instruction smuggling rather than harmless formatting.

## Why It's Important

Transcript-style content can trick an agent or reviewer into treating embedded text as if it came
from a trusted role. That makes it a useful format for carrying hidden instructions across role
boundaries.

## Why The Severity Is Rated High

The default severity is `high` because transcript injection is an explicit attempt to impersonate
conversation structure and authority. In prompt-driven systems, that can materially change how the
content is interpreted.

## How The Rule Works Technically

Promptinel scans segments line by line, looking for alternating role headers and tracking the start
of each sequence. It reports a finding when it sees at least three alternating role lines and the
body includes suspicious instruction content.

## Recommendations For Handling Findings

Flatten the content into ordinary quoted text instead of transcript-like role lines, or remove it
if it is not needed. If the sequence exists for a security test or documentation, label it as a
simulated transcript and keep it away from live prompts.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
