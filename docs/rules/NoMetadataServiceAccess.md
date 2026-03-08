# No Metadata Service Access

[Back to overview](./Overview.md)

| Field            | Value                                                                                                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-metadata-service-access`                                                                                   |
| Default severity | `high`                                                                                                         |
| Summary          | Detects URLs targeting cloud instance metadata endpoints                                                       |
| Description      | Cloud metadata services can expose credentials and environment secrets when accessed from compromised prompts. |

## What This Rule Does

This rule detects direct references to cloud instance metadata endpoints, including full URLs and
snippet-style references to known hosts and paths. It targets prompts that attempt to read cloud
credentials or environment details from the local runtime.

## Why It's Important

Metadata services often expose instance credentials, tokens, and other sensitive runtime data.
Prompt instructions that reach those endpoints are frequently part of credential theft or lateral
movement attempts.

## Why The Severity Is Rated High

The default severity is `high` because metadata service access is a strong indicator of
environment-focused secret collection. In a capable environment, the impact of a successful read is
immediate and significant.

## How The Rule Works Technically

Promptinel checks URL tokens for known metadata hosts and also scans raw segment content for common
metadata host and path snippets. The rule only evaluates when network access is relevant in the
current execution context.

## Recommendations For Handling Findings

Remove instructions that target instance metadata and replace them with safer, explicit test data
where needed. If the reference is part of a security example, make that purpose unambiguous and
avoid presenting it as an actionable step.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
