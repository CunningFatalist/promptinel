# No YAML/JSON Role Fields

| Field            | Value                                                                                                                                         |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Rule ID          | `no-yaml-json-role-fields`                                                                                                                    |
| Default severity | `high`                                                                                                                                        |
| Summary          | Detects embedded role/tool-call protocol payloads                                                                                             |
| Description      | Structured role, tool_call, and function_call payloads embedded in content can spoof agent protocol boundaries and tool invocation semantics. |

## What This Rule Does

This rule detects YAML- or JSON-like payloads embedded in content that define role fields together
with protocol or elevated-role indicators. It targets content that tries to look like native agent
protocol data rather than plain text.

## Why It's Important

Structured protocol payloads can smuggle role or tool semantics into places where they do not
belong. If downstream systems or readers treat the payload as authoritative, the content can cross
instruction or tool boundaries.

## Why The Severity Is Rated High

The default severity is `high` because the rule targets spoofing of agent protocol structure, not
just suspicious wording. That is a direct attack on control-plane trust and tool invocation
semantics.

## How The Rule Works Technically

Promptinel scans the full document for role-field snippets and then requires supporting protocol
fields or elevated-role markers before reporting a finding. This keeps the detector focused on
embedded protocol payloads instead of ordinary structured data.

## Recommendations For Handling Findings

Keep agent protocol objects out of ordinary prompt content unless they are clearly inert test data.
If you need example payloads, isolate them, label them, and avoid mixing them into live prompt
flows where they could be misinterpreted.

After manual review, update the baseline for accepted cases so they stay quiet in future scans.
That applies to reviewed examples, fixtures, and manually checked agent skill resources that you
have decided are safe.
