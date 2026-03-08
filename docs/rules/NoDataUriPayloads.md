# No Data URI Payloads

[Back to overview](./Overview.md)

| Field            | Value                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------- |
| Rule ID          | `no-data-uri-payloads`                                                                   |
| Default severity | `medium`                                                                                 |
| Summary          | Detects embedded base64 data URI payloads                                                |
| Description      | Large embedded data URIs can hide executable or exfiltration payloads in prompt content. |

## What This Rule Does

This rule detects large `data:` URIs that carry base64 payloads directly inside the document. It
focuses on embedded payloads that are more likely to be used for staging content than for ordinary
small inline assets.

## Why It's Important

Inline data URIs can hide substantial payloads from casual review because the dangerous content is
compressed into a single opaque string. They are useful for smuggling scripts, binaries, or
exfiltration material through content that looks self-contained.

## Why The Severity Is Rated Medium

The default severity is `medium` because embedded data URIs are suspicious but not inherently
malicious in every case. They still warrant review because they are a common concealment mechanism
for staged content.

## How The Rule Works Technically

Promptinel scans the full document with a data-URI pattern that extracts the MIME type and base64
payload. The rule then applies additional filtering so it flags payloads that look large or risky
enough to justify a finding instead of matching every small inline asset.

## Recommendations For Handling Findings

Review whether the payload is necessary and whether it is being used to hide content that should be
stored or reviewed in a clearer form. Where possible, replace opaque embedded payloads with normal
files or explicit references that can be inspected directly.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
