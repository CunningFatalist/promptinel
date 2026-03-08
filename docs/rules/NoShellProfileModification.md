# No Shell Profile Modification

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Rule ID          | `no-shell-profile-modification`                                                                                                      |
| Default severity | `high`                                                                                                                               |
| Summary          | Detects write operations targeting shell profile files                                                                               |
| Description      | Writing commands to shell startup profile files can establish persistence and should be treated as high risk in prompt instructions. |

## What This Rule Does

This rule detects flows that combine write intent with shell startup profile targets such as common
shell RC files. It is aimed at instructions that would persist behavior across future shells.

## Why It's Important

Prompt-driven persistence is especially dangerous because the original prompt may disappear while
the profile change remains. A single write to a startup file can keep executing attacker-controlled
content long after the initial interaction.

## Why The Severity Is Rated High

The default severity is `high` because the rule covers persistence against user shell startup
mechanisms. Persistent compromise is more damaging and harder to notice than a single transient
command.

## How The Rule Works Technically

Promptinel performs a flow analysis when filesystem access is relevant. It tracks write-intent
tokens such as redirection and write commands, tracks shell profile path snippets, and reports a
finding when the write and the target appear close enough to form one operation.

## Recommendations For Handling Findings

Do not write prompt-driven content into shell startup files. If you need reproducible environment
setup, keep it in reviewed installation steps or version-controlled scripts that require explicit
user action.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
