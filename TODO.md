# TODO: Rule Backlog (Prioritized)

Source: `/Users/stefan/Desktop/deep-research-report.md`

Priority scale:

- `P0` = critical security coverage gaps (implement first)
- `P1` = high-value precision and attack-surface expansion
- `P2` = defense-in-depth and noise-reduction improvements

## 1) Existing Built-in Rules: Required Adjustments

### P0

- [x] `no-curl-pipe-shell`: Expand beyond direct `curl|sh`/`wget|sh` to cover indirect execution (
  `bash -c "$(curl ...)"`, `sh -c`, PowerShell equivalents, newline/whitespace variants).
- [x] `no-download-execute`: Detect download + execution across command substitution and inline interpreter usage; keep
  multi-signal requirement (`download` + `URL` + `execution`) to avoid false positives.
- [x] `no-staged-download-execution`: Extend flow detection to staged chains like
  `download -> decode/decompress -> execute`, including cross-segment sequences.
- [x] `no-sensitive-file-paths`: Split semantics for `read/exfil` vs `write/persist` intent; broaden path coverage (
  Linux, macOS, Windows credential/profile locations).
- [x] `no-secret-to-network-flow`: Add sinks beyond plain URLs (webhooks, reverse tunnels, transfer binaries, DNS
  channels) and require strong source/action/sink triads.
- [x] `no-secret-exfiltration-intent`: Expand secret + exfil vocabulary (cloud tokens, API artifacts, webhook language)
  and tune distance windows for trusted vs untrusted input.
- [x] `no-metadata-service-access`: Expand metadata endpoint coverage (additional cloud hosts/IP forms, IPv6 variants)
  and detect host references even when URL parsing is bypassed.
- [x] `no-override-capability-flow`: Add capability signals for tool/function-call style execution requests and
  structured role-spoof payloads.

### P1

- [ ] `no-prompt-injection-override`: Reduce documentation/quoted-text false positives; add stronger pattern set for
  untrusted content while keeping deterministic behavior.
- [ ] `no-command-chaining`: Improve shell-context detection for code examples/docs and add encoded chaining operator
  detection (`%3B`, `%26%26`, `%7C`).
- [ ] `no-unsafe-templates`: Strengthen template taint handling so only placeholder-driven execution/network/file
  patterns trigger high-confidence findings.
- [ ] `no-hidden-html-instructions`: Extend hidden-content scanning to additional hidden containers and nested comment
  patterns.
- [ ] `no-suspicious-base64`: Add entropy/shape checks and decoder-coupling heuristics to separate benign blobs from
  executable/exfil payloads.
- [ ] `no-data-uri-payloads`: Add MIME-aware handling and stronger triggering when payloads are
  script/executable-oriented.
- [ ] `no-insecure-http`: Add companion high-risk behavior when insecure HTTP appears together with
  execution/download/tool-invocation intent.

### P2

- [ ] `no-bidi-control-characters`: Improve finding detail (specific rune/class and exact span) and detect
  directionality abuse in URL/path-like tokens.
- [ ] `no-zero-width`: Expand to related invisible formatting characters (for example soft-hyphen/word-joiner families)
  with precise span reporting.

## 2) New Rules to Add

### P0

- [x] `no-powershell-download-cradle` (`Token`/`Flow`): Detect `Invoke-WebRequest`/`DownloadString` +
  `Invoke-Expression` style chains.
- [x] `no-interpreter-inline-exec` (`Token`): Detect inline execution flags (`python -c`, `node -e`, `ruby -e`,
  `php -r`, `perl -e`) with execution context.
- [x] `no-role-header-spoofing` (`Segment`): Detect `SYSTEM:`, `DEVELOPER:`, `TOOLS:` and related role header spoof
  patterns.
- [x] `no-yaml-json-role-fields` (`Document`/`Token`): Detect embedded role/tool-call payloads (`role`, `tool_calls`,
  `function_call`, `arguments`) that can spoof agent protocols.
- [x] `no-shell-profile-modification` (`Token`/`Flow`): Detect write operations targeting shell startup/profile files.
- [x] `no-ssh-config-manipulation` (`Token`/`Flow`): Detect write operations to `~/.ssh/config`, `authorized_keys`, and
  related SSH trust stores.
- [x] `no-tunnel-and-reverse-shell` (`Token`/`Flow`): Detect reverse shell and tunneling instructions (`nc -e`,
  `/dev/tcp`, `ssh -R`, `ngrok`, `cloudflared`).
- [x] `no-webhook-exfiltration` (`Token`/`Flow`): Detect data transfer instructions to webhook/request-bin style sinks,
  coupled with secret/file signals.
- [x] `no-mixed-script-identifiers` (`Token`): Detect homoglyph/mixed-script spoofing in identifier-like tokens and
  hostnames.

### P1

- [ ] `no-transcript-injection` (`Segment`): Detect fake chat transcripts (`User:`, `Assistant:` role alternation) used
  as instruction smuggling.
- [ ] `no-shell-heredoc-payload` (`Document`): Detect heredoc payload containers likely used to stage scripts.
- [ ] `no-gitconfig-credential-helper` (`Token`): Detect risky credential-helper and HTTP header rewrites in
  `git config` instructions.
- [ ] `no-dns-exfiltration` (`Flow`): Detect DNS-based exfil chains (`nslookup`/`dig` + secret source + external
  domain).
- [ ] `no-tainted-placeholder-instructions` (`Token`/`Segment`): Detect tainted template placeholders near
  override/capability execution language.
- [ ] `no-template-network-fetch` (`Token`): Detect template expressions that dynamically build or trigger network/tool
  fetch behavior.
- [ ] `no-url-encoded-command-payload` (`Token`): Detect encoded command operators and payloads intended for
  decode-then-execute flows.

### P2

- [ ] `no-nonstandard-whitespace` (`Document`): Detect uncommon whitespace used for instruction hiding when combined
  with actionable content.
- [ ] `no-hidden-directionality` (`Token`): Detect suspicious RTL/LTR directionality usage in non-natural-language
  tokens.
- [ ] `no-multilayer-encoding` (`Flow`): Detect multi-layer payload staging (base64 + URL encoding + decode/decompress
  steps).

## 3) Delivery Checklist for Every Rule Change

- [x] Add deterministic unit tests: at least one positive case, one negative case, and one false-positive guard case.
- [x] Register new built-ins in `internal/rules/builtin/registry.go` and include metadata/docs entries.
- [x] Keep finding messages stable for baseline compatibility.
- [x] Update `README.md` rule catalog and configuration examples for new IDs/severity defaults.
- [x] Validate with `make fmt fix vet vuln lint test` before merging.
