# Rule Documentation Overview

Promptinel ships with built-in rule documentation in [`docs/rules/`](../rules/). Each rule has its
own page with the same structure:

- a summary table that mirrors `promptinel rules list --description`
- an explanation of what the rule detects
- severity rationale
- implementation notes
- recommendations for triaging and handling findings

Use [`../rules/Template.md`](../rules/Template.md) when adding documentation for a new rule or
refreshing an existing one.

## Rule Index

| Rule                                                                                | Rule ID                               | Severity | Summary                                                                      |
| ----------------------------------------------------------------------------------- | ------------------------------------- | -------- | ---------------------------------------------------------------------------- |
| [No Bidi Control Characters](../rules/NoBidiControlCharacters.md)                   | `no-bidi-control-characters`          | `high`   | Detects bidirectional text control characters                                |
| [No Command Chaining](../rules/NoCommandChaining.md)                                | `no-command-chaining`                 | `medium` | Detects chained shell command operators                                      |
| [No Curl/Wget Pipe To Shell](../rules/NoCurlPipeShell.md)                           | `no-curl-pipe-shell`                  | `high`   | Detects direct piping from network download commands into shell interpreters |
| [No Data URI Payloads](../rules/NoDataUriPayloads.md)                               | `no-data-uri-payloads`                | `medium` | Detects embedded base64 data URI payloads                                    |
| [No DNS Exfiltration](../rules/NoDnsExfiltration.md)                                | `no-dns-exfiltration`                 | `high`   | Detects DNS-based exfiltration chains                                        |
| [No Download Then Execute](../rules/NoDownloadExecute.md)                           | `no-download-execute`                 | `medium` | Detects mixed download and execution signals in one segment                  |
| [No Git Config Credential Helper Rewrites](../rules/NoGitconfigCredentialHelper.md) | `no-gitconfig-credential-helper`      | `high`   | Detects risky git credential-helper and HTTP header rewrites                 |
| [No Hidden Directionality](../rules/NoHiddenDirectionality.md)                      | `no-hidden-directionality`            | `medium` | Detects hidden RTL/LTR controls inside identifier-like tokens                |
| [No Hidden HTML Instructions](../rules/NoHiddenHtmlInstructions.md)                 | `no-hidden-html-instructions`         | `medium` | Detects suspicious instructions inside HTML comments                         |
| [No Insecure HTTP URL](../rules/NoInsecureHttp.md)                                  | `no-insecure-http`                    | `low`    | Detects plaintext HTTP URLs                                                  |
| [No Interpreter Inline Exec](../rules/NoInterpreterInlineExec.md)                   | `no-interpreter-inline-exec`          | `high`   | Detects inline interpreter execution flags                                   |
| [No Metadata Service Access](../rules/NoMetadataServiceAccess.md)                   | `no-metadata-service-access`          | `high`   | Detects URLs targeting cloud instance metadata endpoints                     |
| [No Mixed Script Identifiers](../rules/NoMixedScriptIdentifiers.md)                 | `no-mixed-script-identifiers`         | `high`   | Detects mixed-script identifier and hostname spoofing                        |
| [No Multilayer Encoding](../rules/NoMultilayerEncoding.md)                          | `no-multilayer-encoding`              | `high`   | Detects multi-layer encoded payload staging                                  |
| [No Nonstandard Whitespace](../rules/NoNonstandardWhitespace.md)                    | `no-nonstandard-whitespace`           | `medium` | Detects uncommon whitespace near actionable prompt content                   |
| [No Override Capability Flow](../rules/NoOverrideCapabilityFlow.md)                 | `no-override-capability-flow`         | `high`   | Detects prompt overrides combined with actionable capability signals         |
| [No PowerShell Download Cradle](../rules/NoPowershellDownloadCradle.md)             | `no-powershell-download-cradle`       | `high`   | Detects PowerShell download cradle chains                                    |
| [No Prompt Override Instructions](../rules/NoPromptInjectionOverride.md)            | `no-prompt-injection-override`        | `medium` | Detects override phrases, with stricter matching in lower-trust regions      |
| [No Role Header Spoofing](../rules/NoRoleHeaderSpoofing.md)                         | `no-role-header-spoofing`             | `high`   | Detects structured role-header spoof patterns                                |
| [No Secret Exfiltration Intent](../rules/NoSecretExfiltrationIntent.md)             | `no-secret-exfiltration-intent`       | `high`   | Detects secret/exfiltration intent with broader windows in lower-trust spans |
| [No Secret To Network Flow](../rules/NoSecretToNetworkFlow.md)                      | `no-secret-to-network-flow`           | `high`   | Detects exfiltration chains with broader windows across lower-trust spans    |
| [No Sensitive File Paths](../rules/NoSensitiveFilePaths.md)                         | `no-sensitive-file-paths`             | `high`   | Detects references to commonly targeted sensitive local files                |
| [No Shell Heredoc Payload](../rules/NoShellHeredocPayload.md)                       | `no-shell-heredoc-payload`            | `high`   | Detects suspicious heredoc payload containers used to stage scripts          |
| [No Shell Profile Modification](../rules/NoShellProfileModification.md)             | `no-shell-profile-modification`       | `high`   | Detects write operations targeting shell profile files                       |
| [No SSH Config Manipulation](../rules/NoSshConfigManipulation.md)                   | `no-ssh-config-manipulation`          | `high`   | Detects write operations to SSH trust stores                                 |
| [No Staged Download Execution](../rules/NoStagedDownloadExecution.md)               | `no-staged-download-execution`        | `high`   | Detects multi-step download-then-execute flows across segments               |
| [No Suspicious Base64 Payload](../rules/NoSuspiciousBase64.md)                      | `no-suspicious-base64`                | `medium` | Detects long base64-like payloads                                            |
| [No Tainted Placeholder Instructions](../rules/NoTaintedPlaceholderInstructions.md) | `no-tainted-placeholder-instructions` | `high`   | Detects lower-trust placeholders near override or capability language        |
| [No Template Network Fetch](../rules/NoTemplateNetworkFetch.md)                     | `no-template-network-fetch`           | `medium` | Detects dynamic network or tool fetch behavior in templates                  |
| [No Transcript Injection](../rules/NoTranscriptInjection.md)                        | `no-transcript-injection`             | `high`   | Detects transcript-style role alternation used for instruction smuggling     |
| [No Tunnel And Reverse Shell](../rules/NoTunnelAndReverseShell.md)                  | `no-tunnel-and-reverse-shell`         | `high`   | Detects reverse shell and tunneling instructions                             |
| [No Unsafe Templates](../rules/NoUnsafeTemplates.md)                                | `no-unsafe-templates`                 | `medium` | Detects risky template expressions with execution or exfiltration intent     |
| [No URL Encoded Command Payload](../rules/NoUrlEncodedCommandPayload.md)            | `no-url-encoded-command-payload`      | `high`   | Detects URL-encoded command payloads intended for execution                  |
| [No Webhook Exfiltration](../rules/NoWebhookExfiltration.md)                        | `no-webhook-exfiltration`             | `high`   | Detects secret/file exfiltration chains targeting webhook sinks              |
| [No YAML/JSON Role Fields](../rules/NoYamlJsonRoleFields.md)                        | `no-yaml-json-role-fields`            | `high`   | Detects embedded role/tool-call protocol payloads                            |
| [No Zero Width Characters](../rules/NoZeroWidth.md)                                 | `no-zero-width`                       | `high`   | Detects hidden zero-width Unicode characters                                 |
| [Skill Has Bundled Resources](../rules/SkillHasBundledResources.md)                 | `skill-has-bundled-resources`         | `low`    | Detects skills that reference bundled local resources                        |

## Custom Rules

Promptinel also supports config-defined custom regex rules. They are not part of the built-in rule
catalog exposed by `promptinel rules list` or `promptinel rules describe`, because they only exist
when loaded from a specific config file. See [Custom Rules](../rules/Custom.md) for the generic
behavior and documentation model.
