# No Secret To Network Flow

[Back to overview](../Rules/Overview.md)

| Field            | Value                                                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-secret-to-network-flow`                                                                                                     |
| Default severity | `high`                                                                                                                          |
| Summary          | Detects secret-source to outbound-network exfiltration chains                                                                   |
| Description      | The combination of secret references, exfiltration language, and outbound network sinks suggests a high-risk exfiltration flow. |

## What This Rule Does

This rule detects a full exfiltration chain that starts with a secret source, includes an outbound
transfer action, and ends at a network sink. It is stricter than an intent-only rule because it
looks for the whole sequence.

## Why It's Important

When a prompt tells an agent where to get secrets, how to move them, and where to send them, the
risk is no longer hypothetical. That pattern maps closely to real-world data exfiltration behavior.

## Why The Severity Is Rated High

The default severity is `high` because the rule models a concrete source-action-sink flow. This is
strong evidence of an attempted outbound leak rather than a weak contextual warning.

## How The Rule Works Technically

Promptinel performs a flow analysis over all tokenized segments when the environment can access the
network and secrets are in scope. It tracks secret-source tokens, exfiltration action tokens, and
outbound sink tokens, then looks for ordered triads within a bounded token window. That window is
expanded when the source-to-sink range crosses lower-trust provenance spans.

## Recommendations For Handling Findings

Treat the finding as a likely exfiltration attempt and remove the outbound flow. If the content is
part of a defensive example or regression test, keep it clearly marked, reduce its blast radius,
and avoid leaving it where it could be reused as a live instruction.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
