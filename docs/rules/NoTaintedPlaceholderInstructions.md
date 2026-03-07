# No Tainted Placeholder Instructions

[Back to overview](../Rules/Overview.md)

| Field            | Value                                                                                                                                                 |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-tainted-placeholder-instructions`                                                                                                                 |
| Default severity | `high`                                                                                                                                                |
| Summary          | Detects tainted placeholders near override or capability language                                                                                     |
| Description      | Untrusted placeholders placed next to override, execution, or capability language can act as injection boundaries and should be treated as high risk. |

## What This Rule Does

This rule detects placeholder syntax in untrusted content when it appears close to override,
execution, or other capability-oriented language. It is designed to catch injection boundaries
where external data can be substituted into a dangerous instruction frame.

## Why It's Important

Placeholders can turn a static-looking prompt into a dynamic attack surface. When untrusted data is
inserted near powerful instructions, the placeholder becomes the point where malicious content can
enter the workflow.

## Why The Severity Is Rated High

The default severity is `high` because the rule combines untrusted input with nearby high-risk
instruction language. That is a realistic and common structure for prompt injection and tool abuse.

## How The Rule Works Technically

Promptinel only evaluates this rule in untrusted contexts. It finds placeholder matches in the
document, examines a bounded window around each placeholder, and reports a finding when the nearby
content contains override, execution, or capability signals.

## Recommendations For Handling Findings

Avoid placing untrusted placeholders next to instructions that control tools, secrets, shell
execution, or network behavior. If placeholders are necessary, constrain and validate the inserted
values and keep them away from control-plane language.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
