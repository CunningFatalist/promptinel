# No Curl/Wget Pipe To Shell

| Field            | Value                                                                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-curl-pipe-shell`                                                                                 |
| Default severity | `high`                                                                                               |
| Summary          | Detects direct piping from network download commands into shell interpreters                         |
| Description      | Piping curl/wget output directly to shell interpreters is a high-risk remote code execution pattern. |

## What This Rule Does

This rule detects prompt content that pipes the output of `curl`, `wget`, or equivalent download
commands directly into a shell or inline interpreter. It also catches related PowerShell execution
patterns that achieve the same result.

## Why It's Important

This is one of the clearest remote execution patterns in shell-oriented workflows. It turns remote
content into code without an explicit inspection step and makes it easy to hide malicious payloads
behind a single command.

## Why The Severity Is Rated High

The default severity is `high` because the pattern is a short, direct path from the network to
execution. False positives are easy to review, while a missed real case can lead directly to
arbitrary code execution.

## How The Rule Works Technically

Promptinel tokenizes each executable segment and checks for download signals together with pipes to
shell interpreters, inline interpreter execution, or PowerShell execution signals. The rule only
fires when the current context allows both network access and shell execution.

## Recommendations For Handling Findings

Replace one-step download-and-execute flows with a safer process. Download content separately,
verify the source and integrity, review the script, and only then execute it if it is genuinely
required.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
