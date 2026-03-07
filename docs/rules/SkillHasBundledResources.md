# Skill Has Bundled Resources

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `skill-has-bundled-resources` |
| Default severity | `low` |
| Summary | Detects skills that reference bundled local resources |
| Description | Skills can include scripts, references, or assets outside SKILL.md. Promptinel does not review those transitively, so they should be reviewed manually and excluded after acceptance if appropriate. |

## What This Rule Does

This rule detects Claude Skills that reference bundled local resources such as scripts, assets, or
reference files outside `SKILL.md`. It reports the skill because Promptinel does not recursively
scan or reason about those referenced resources as part of the skill document itself.

## Why It's Important

A skill may look safe at the top level while delegating meaningful behavior to bundled scripts or
other local files. Those referenced resources can materially change what the skill does, so they
need separate review.

## Why The Severity Is Rated Low

The default severity is `low` because bundled resources are not malicious by themselves. The rule
exists as a review reminder: the risk depends on what the referenced files actually contain and how
they are used.

## How The Rule Works Technically

Promptinel reads the skill context gathered during scanning and checks whether the skill references
bundled resources. When it does, the rule reports the skill reference position and includes a small
sample of the referenced paths in the finding message.

## Recommendations For Handling Findings

Manually review the referenced scripts, assets, or support files before accepting the skill as
safe. If you have reviewed the bundled Claude Skill scripts or other resources and are satisfied
they are safe, update the baseline and, where appropriate, exclude the accepted skill directory or
accepted resources from future noise.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
