# No Prompt Override Instructions

| Field            | Value                                                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-prompt-injection-override`                                                                                             |
| Default severity | `medium`                                                                                                                   |
| Summary          | Detects common prompt-injection override phrases                                                                           |
| Description      | Instruction-override language often appears in prompt-injection attempts designed to bypass system and developer controls. |

## What This Rule Does

This rule detects common prompt-injection phrases that attempt to override or ignore higher
priority instructions. In lower-trust regions, it also checks an expanded set of phrases that are
more suspicious when user-controlled or remotely sourced content is involved.

## Why It's Important

Override phrases are one of the most recognizable prompt-injection signals. Even when they are not
paired with a concrete action yet, they often mark the beginning of an attempt to bypass safety or
policy boundaries.

## Why The Severity Is Rated Medium

The default severity is `medium` because these phrases can appear in documentation, discussions,
and tests as well as in real attacks. They are important enough to review, but not every mention is
an exploit.

## How The Rule Works Technically

Promptinel scans the full document for known override phrases and reports the first match position.
When the matched region is marked untrusted or tainted, it also evaluates a broader phrase list
that is intentionally more conservative.

## Recommendations For Handling Findings

If the phrase is actionable, remove it or rewrite the content so it cannot be interpreted as an
instruction override. If it is only present in an explanation or test, add enough context that the
reader and the scanner output are easy to triage.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
