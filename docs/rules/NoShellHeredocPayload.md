# No Shell Heredoc Payload

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `no-shell-heredoc-payload` |
| Default severity | `high` |
| Summary | Detects suspicious heredoc payload containers used to stage scripts |
| Description | Heredocs can stage executable payloads or exfiltration scripts inline, especially when paired with shell or file-write commands. |

## What This Rule Does

This rule detects heredoc blocks that look like they are being used to stage executable or
exfiltration content inline. It is aimed at shell-style payload containers rather than harmless
multi-line text blocks.

## Why It's Important

Heredocs are convenient for embedding a large payload inside an otherwise short command. That makes
them useful for writing scripts, staging data, or building command files without making the content
obvious at first glance.

## Why The Severity Is Rated High

The default severity is `high` because heredoc staging is commonly used to deliver substantial
payloads for later execution or transfer. In shell-capable environments, the step from staging to
execution is often very small.

## How The Rule Works Technically

Promptinel scans the full document for heredoc start markers, validates the heredoc terminator, and
inspects both the preamble and the body for suspicious staging signals. A finding is reported when
the surrounding command and the embedded content together look like payload construction.

## Recommendations For Handling Findings

Move complex scripts or data into reviewed files instead of embedding them inline in heredocs. If a
heredoc is present for a test or example, reduce it to inert content and label the example so it is
easy to triage.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
