# No Staged Download Execution

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-staged-download-execution`                                                                                         |
| Default severity | `high`                                                                                                                 |
| Summary          | Detects multi-step download-then-execute flows across segments                                                         |
| Description      | Attack prompts often split download and execution instructions across separate sections to avoid local pattern checks. |

## What This Rule Does

This rule detects multi-step flows where content is downloaded in one part of the document and
executed later in another part. It is built for staged instructions that try to evade simpler
single-segment detection.

## Why It's Important

Attackers often split a dangerous workflow into multiple lines or sections so no single snippet
looks obviously malicious. Detecting the whole chain is important because that is how real prompt
attacks often appear in practice.

## Why The Severity Is Rated High

The default severity is `high` because the rule models an evasive download-to-execution sequence.
The staging makes it harder to review, but the operational outcome is still remote execution.

## How The Rule Works Technically

Promptinel performs a cross-segment flow analysis when both network and shell capabilities are
available. It identifies a download stage, optional transform stage, and later execution stage, and
it avoids double-reporting obvious same-segment chained commands that are better handled by other
rules.

## Recommendations For Handling Findings

Break the workflow apart and remove the execution stage unless it is truly necessary and separately
reviewed. If the sequence is intentionally preserved for testing, keep it in controlled fixtures and
make the staging purpose explicit.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
