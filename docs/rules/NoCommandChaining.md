# No Command Chaining

[Back to overview](./Overview.md)

| Field            | Value                                            |                                                        |
| ---------------- | ------------------------------------------------ | ------------------------------------------------------ |
| Rule ID          | `no-command-chaining`                            |                                                        |
| Default severity | `medium`                                         |                                                        |
| Summary          | Detects chained shell command operators          |                                                        |
| Description      | Shell chaining operators like `;`, `&&`, and `'` | `'` often indicate complex or evasive execution flows. |

## What This Rule Does

This rule detects shell command chaining operators in executable content. It looks for direct
operators, operators embedded in code blocks, and encoded forms that still imply chained shell
behavior.

## Why It's Important

Command chaining is a common way to compress multiple actions into one prompt or one generated
command. It often turns a benign-looking instruction into a compound flow that downloads, modifies,
or executes more than the reader expects.

## Why The Severity Is Rated Medium

The default severity is `medium` because chaining is suspicious but not always malicious on its
own. It still deserves review because it frequently appears as one stage in more dangerous
execution or persistence flows.

## How The Rule Works Technically

Promptinel uses token-based checks when shell execution is possible in the current context. It
looks for chaining operators in tokenized commands, scans code blocks for shell chaining patterns,
and runs a segment-level pass for encoded chaining so obfuscated forms are still detected.

## Recommendations For Handling Findings

Split chained commands into separate reviewed steps and keep the intent explicit. If the chaining
is only present in a safe example or fixture, label it clearly and keep it isolated from live
instructions.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
