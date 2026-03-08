# No Git Config Credential Helper Rewrites

[Back to overview](./Overview.md)

| Field            | Value                                                                                                         |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-gitconfig-credential-helper`                                                                              |
| Default severity | `high`                                                                                                        |
| Summary          | Detects risky git credential-helper and HTTP header rewrites                                                  |
| Description      | Prompted git config rewrites can persist credentials or inject authorization headers into future Git traffic. |

## What This Rule Does

This rule detects `git config` rewrites that modify credential helpers or HTTP extra headers. It
targets instructions that can cause Git to persist secrets locally or attach attacker-controlled
authentication data to future requests.

## Why It's Important

Git configuration changes are often durable and affect later commands, not just the immediate
prompt. That makes them an attractive persistence and credential-manipulation mechanism in tool-use
environments.

## Why The Severity Is Rated High

The default severity is `high` because the rule covers durable configuration changes that can leak
credentials or alter trusted network behavior after the original prompt has finished. The impact is
broader than a one-off command.

## How The Rule Works Technically

Promptinel scans each segment with a `git config` pattern and extracts the configuration key and
value. It raises a finding when the key targets `credential.helper` with risky helper values or
when an `http.*.extraheader` setting appears to inject authorization-related headers.

## Recommendations For Handling Findings

Avoid prompt-driven changes to Git credential storage or HTTP header configuration. If a workflow
really needs Git authentication, use short-lived credentials and explicit user-managed setup rather
than instructions that rewrite persistent configuration.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
