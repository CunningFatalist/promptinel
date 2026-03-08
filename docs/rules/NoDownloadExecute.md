# No Download Then Execute

[Back to overview](./Overview.md)

| Field            | Value                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-download-execute`                                                                                   |
| Default severity | `medium`                                                                                                |
| Summary          | Detects mixed download and execution signals in one segment                                             |
| Description      | Combining remote download references with execution commands can indicate remote code execution intent. |

## What This Rule Does

This rule detects segments that combine a remote URL, download behavior, and execution behavior in
the same place. It is designed to catch compact instructions that fetch something and run it
immediately.

## Why It's Important

Many prompt-driven attacks rely on blending download and execution into a single command so the
payload is never reviewed separately. Even when the command is incomplete, this combination is a
strong indicator of risky intent.

## Why The Severity Is Rated Medium

The default severity is `medium` because the pattern is serious but somewhat broader than the most
explicit execution chains. It can appear in demonstrations or partial snippets, but it still
deserves prompt review.

## How The Rule Works Technically

Promptinel tokenizes executable segments and checks for three ingredients together: a URL token, a
download signal, and an execution command or inline interpreter execution pattern. The rule only
evaluates when both network access and shell execution are relevant in the current context.

## Recommendations For Handling Findings

Separate download and execution into distinct reviewed steps, or remove the execution stage
entirely if the content is only meant to fetch data. If the pattern is retained for testing or
documentation, mark it clearly as inert and keep it isolated from live prompts.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
