# No SSH Config Manipulation

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                 |
| ---------------- | --------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-ssh-config-manipulation`                                                                                          |
| Default severity | `high`                                                                                                                |
| Summary          | Detects write operations to SSH trust stores                                                                          |
| Description      | Modifying SSH config and trust-store files can establish persistent remote access and should be treated as high risk. |

## What This Rule Does

This rule detects flows that combine write intent with SSH configuration or trust-store targets. It
looks for instructions that would alter how SSH trusts hosts, keys, or connection settings.

## Why It's Important

SSH trust stores and config files are durable control points. Changing them can weaken host
verification, redirect connections, or establish persistence for later remote access.

## Why The Severity Is Rated High

The default severity is `high` because the pattern targets long-lived trust and access settings.
When successful, the effect can outlast the original prompt and reshape future remote access.

## How The Rule Works Technically

Promptinel performs a filesystem-aware flow analysis and collects write-intent tokens plus SSH
trust-store path snippets. It reports a finding when those signals appear in an ordered sequence
close enough to represent one write operation.

## Recommendations For Handling Findings

Avoid prompt-driven edits to SSH config, `known_hosts`, authorized key material, or related trust
stores. Use reviewed administrative workflows instead, with explicit user intent and normal change
control.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
