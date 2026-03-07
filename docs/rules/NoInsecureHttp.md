# No Insecure HTTP URL

[Back to overview](../Rules/Overview.md)

| Field | Value |
| --- | --- |
| Rule ID | `no-insecure-http` |
| Default severity | `low` |
| Summary | Detects plaintext HTTP URLs |
| Description | HTTP URLs can be tampered with in transit and are risky when prompts retrieve executable instructions. |

## What This Rule Does

This rule detects `http://` URLs in network-capable contexts. It also distinguishes cases where the
HTTP URL appears alongside download or execution signals, which makes the transport risk more
serious.

## Why It's Important

Plain HTTP provides no transport integrity. If a prompt uses it to fetch scripts, templates, or
instructions, an attacker on the network path can modify the content before it is consumed.

## Why The Severity Is Rated Low

The default severity is `low` because an HTTP URL alone is only a transport warning, not proof of
malicious intent. It is still valuable as an early warning and becomes more important when combined
with download or execution behavior.

## How The Rule Works Technically

Promptinel examines URL tokens in tokenized segments when network access is relevant. It reports
any URL that starts with `http://` and adjusts the finding message when surrounding tokens suggest
download or execution activity in the same segment.

## Recommendations For Handling Findings

Change the reference to `https://` or another integrity-protected source where possible. If the
HTTP URL is intentional and truly low risk, document why it is acceptable and avoid pairing it with
automatic download or execution behavior.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked Claude Skill resources that you
have decided are safe.
