# No Hidden HTML Instructions

| Field            | Value                                                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-hidden-html-instructions`                                                                                           |
| Default severity | `medium`                                                                                                                |
| Summary          | Detects suspicious instructions inside HTML comments                                                                    |
| Description      | Hidden HTML comments can conceal instruction overrides and execution guidance in otherwise benign-looking prompt files. |

## What This Rule Does

This rule detects hidden instruction content inside HTML comments and related hidden containers. It
is designed to catch prompt text that looks harmless when rendered but still carries actionable
instructions in the source.

## Why It's Important

HTML comments and hidden containers are an easy place to smuggle overrides, execution hints, or
template directives into content that appears clean to a human reader. That makes them useful for
instruction smuggling and review evasion.

## Why The Severity Is Rated Medium

The default severity is `medium` because hidden HTML can be legitimate in templates and generated
content, but it becomes risky when it carries instruction-like material. The signal is strong
enough to review carefully without treating every comment as a direct compromise.

## How The Rule Works Technically

Promptinel runs several document-level checks: suspicious HTML comments, suspicious hidden
containers, and suspicious template containers. A finding is reported when any of those detectors
sees hidden content that looks like override, execution, or other actionable guidance.

## Recommendations For Handling Findings

Move instructions out of hidden containers and make them explicit, or remove them entirely if they
should not be present. If the content is intentionally hidden for a safe template test, document
that clearly and keep it separated from production prompts.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
