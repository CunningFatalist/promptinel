# No PowerShell Download Cradle

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                                                 |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-powershell-download-cradle`                                                                                                                       |
| Default severity | `high`                                                                                                                                                |
| Summary          | Detects PowerShell download cradle chains                                                                                                             |
| Description      | PowerShell download cradle patterns like Invoke-WebRequest or DownloadString piped into Invoke-Expression indicate high-risk remote execution intent. |

## What This Rule Does

This rule detects PowerShell download cradle behavior, where content is fetched from the network
and then immediately executed. It covers both obvious command sequences and common PowerShell
variants used to achieve the same effect.

## Why It's Important

PowerShell download cradles are a widely used remote execution technique in Windows-centric
environments. They are compact, expressive, and easy to hide inside prompts or generated commands.

## Why The Severity Is Rated High

The default severity is `high` because the pattern directly connects remote retrieval with code
execution. In a capable environment, that is enough to deliver and run attacker-controlled payloads
with minimal friction.

## How The Rule Works Technically

Promptinel performs a flow check across tokenized segments when both shell execution and network
access are possible. It looks for PowerShell download signals followed by execution signals such as
`Invoke-Expression`, and it also detects common variants like `New-Object .Net` based cradles.

## Recommendations For Handling Findings

Do not execute remotely retrieved PowerShell content inline. Download content separately, verify
it, and run only reviewed scripts from trusted locations if that workflow is truly necessary.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
