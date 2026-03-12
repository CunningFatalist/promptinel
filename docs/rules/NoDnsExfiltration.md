# No DNS Exfiltration

| Field            | Value                                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Rule ID          | `no-dns-exfiltration`                                                                                                    |
| Default severity | `high`                                                                                                                   |
| Summary          | Detects DNS-based exfiltration chains                                                                                    |
| Description      | DNS lookup utilities combined with secret sources and external domains strongly suggest DNS-based exfiltration behavior. |

## What This Rule Does

This rule detects document flows that combine secret sources, DNS lookup actions, and external
domain targets. It is aimed at prompts that turn DNS requests into a covert channel for leaking
data.

## Why It's Important

DNS traffic is often allowed in environments where other egress is restricted, which makes it an
attractive exfiltration path. A prompt that reads secret material and then encodes it into DNS
queries is a strong sign of malicious behavior.

## Why The Severity Is Rated High

The default severity is `high` because the rule models a concrete exfiltration chain rather than a
weak single signal. When it matches, the path from secret access to outbound transfer is short and
high impact.

## How The Rule Works Technically

Promptinel performs a flow analysis across tokenized segments when the context allows network
access and secrets are in scope. It tracks secret-source tokens, DNS sink commands, and external
domain signals, then looks for source-action-sink sequences within a bounded token window.

## Recommendations For Handling Findings

Treat the finding as a likely exfiltration attempt unless you can show the content is only
describing the pattern. Remove the DNS transfer behavior, or rewrite the example so the dangerous
chain is clearly inert and not presented as an actionable instruction.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
