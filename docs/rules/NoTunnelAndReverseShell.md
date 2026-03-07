# No Tunnel And Reverse Shell

[Back to overview](../Rules/Overview.md)

| Field            | Value                                                                                                             |
| ---------------- | ----------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-tunnel-and-reverse-shell`                                                                                     |
| Default severity | `high`                                                                                                            |
| Summary          | Detects reverse shell and tunneling instructions                                                                  |
| Description      | Reverse shell and tunnel setup commands can establish unauthorized remote control channels and should be blocked. |

## What This Rule Does

This rule detects reverse shell patterns and tunneling instructions such as common tunnel tools,
SSH reverse forwarding, and shell-spawning netcat variants. It covers both raw snippet matches and
tokenized command patterns.

## Why It's Important

Reverse shells and tunnels establish remote control channels from the local environment to an
external operator. That is a direct compromise pattern, not merely a suspicious precursor.

## Why The Severity Is Rated High

The default severity is `high` because the rule targets explicit remote-control behavior. If the
environment can execute shell commands and access the network, the operational impact can be severe
immediately.

## How The Rule Works Technically

Promptinel first scans the normalized document for known reverse-shell snippets. It then performs a
flow-aware token pass to detect tunnel tool names and command-specific flags such as `ssh -R` or
`nc -e`, but only when both shell execution and network access are relevant.

## Recommendations For Handling Findings

Remove the remote-control instructions and replace them with safe, non-operational descriptions if
the material is educational. Do not leave live reverse shell or tunnel commands in prompts,
templates, or agent-accessible content.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
