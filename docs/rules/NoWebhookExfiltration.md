# No Webhook Exfiltration

[Back to overview](./Overview.md)

| Field            | Value                                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Rule ID          | `no-webhook-exfiltration`                                                                                                      |
| Default severity | `high`                                                                                                                         |
| Summary          | Detects secret/file exfiltration chains targeting webhook sinks                                                                |
| Description      | Webhook and request-bin sinks combined with sensitive data signals and transfer actions indicate likely exfiltration behavior. |

## What This Rule Does

This rule detects flows that combine a sensitive source, a transfer action, and a webhook-style
sink such as a request bin or webhook endpoint. It covers both secret exfiltration and file-based
exfiltration patterns.

## Why It's Important

Webhook sinks are simple to create and easy to abuse for outbound collection. When a prompt tells an
agent what to steal, how to send it, and which webhook to use, the result is a practical
exfiltration workflow.

## Why The Severity Is Rated High

The default severity is `high` because the rule models a complete source-action-sink chain aimed at
an outbound collection endpoint. That is strong evidence of malicious transfer behavior.

## How The Rule Works Technically

Promptinel performs a flow analysis over tokenized segments when network access is available and the
environment can reach secrets or files. It tracks source signals, transfer actions, and webhook
sinks, then reports a finding when they appear in the expected order within a bounded token window.

## Recommendations For Handling Findings

Treat the finding as a likely exfiltration attempt unless you can show it is only an inert example.
Remove the webhook destination and transfer logic, or isolate the example in tightly controlled test
material.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
