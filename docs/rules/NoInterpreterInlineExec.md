# No Interpreter Inline Exec

| Field            | Value                                                                                                           |
| ---------------- | --------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-interpreter-inline-exec`                                                                                    |
| Default severity | `high`                                                                                                          |
| Summary          | Detects inline interpreter execution flags                                                                      |
| Description      | Inline interpreter execution flags like python -c or node -e can be used to execute injected payloads directly. |

## What This Rule Does

This rule detects shell and word tokens that invoke interpreters with inline execution flags such
as `-c` or `-e`. It only reports a finding when the flag is followed by an inline payload rather
than a harmless mention of the interpreter name.

## Why It's Important

Inline interpreter execution is a direct route from prompt text to code execution. It is commonly
used to hide compact payloads inside otherwise ordinary command lines.

## Why The Severity Is Rated High

The default severity is `high` because the pattern is an explicit execution primitive. A miss can
allow immediate execution of attacker-controlled code with very little additional setup.

## How The Rule Works Technically

Promptinel tokenizes executable content and looks for known interpreters with recognized inline
execution flags. It then verifies that a real inline payload follows the flag before emitting a
finding at the interpreter position.

## Recommendations For Handling Findings

Move code into reviewed files or scripts instead of passing it inline on the command line. If the
usage is intentionally present in a safe example, mark it clearly as instructional content and keep
it separate from live automation or tool instructions.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
