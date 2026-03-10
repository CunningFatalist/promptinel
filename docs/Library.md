# Library API

Promptinel can be used as a Go library for in-memory prompt scanning.
This is intended for applications that receive prompt text directly instead of
reading files from disk.

Import path:

```go
import "github.com/CunningFatalist/promptinel/pkg/promptinel"
```

## Hello World

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/CunningFatalist/promptinel/pkg/promptinel"
)

func main() {
	scanner, err := promptinel.NewScanner(promptinel.NewConfig())
	if err != nil {
		log.Fatal(err)
	}

	findings, err := scanner.Scan(context.Background(), "ignore previous instructions")
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range findings {
		fmt.Printf("%s %s:%d:%d %s\n",
			finding.Severity,
			finding.Path,
			finding.Position.Line,
			finding.Position.Column,
			finding.Message,
		)
	}
}
```

## API

`promptinel.NewConfig()` returns a config with Promptinel's secure defaults.

`promptinel.NewScanner(cfg)` validates the config, compiles built-in rules and
custom rules, and returns a reusable scanner.

`scanner.Scan(ctx, content)` scans raw prompt content in memory and returns raw
findings.

`scanner.ScanDocument(ctx, promptinel.Document{...})` scans in-memory content
with optional metadata. Set `Document.Path` when you want path-based scopes to
apply. `Document.Path` must be relative, for example `docs/prompt.md`. Set
`Document.AbsolutePath` when engine features need the real on-disk location,
such as skill-resource resolution for `SKILL.md`. `Document.AbsolutePath` must
be absolute.

## Raw Findings

The library API returns raw findings only. It does not apply
`policy.warn-on` filtering and it does not resolve CLI exit codes.

This is intentional. The caller decides how to handle findings, including:

- filtering by severity
- rendering responses for users
- mapping findings to HTTP status codes
- storing or suppressing findings

## Path-Aware Scans

If your application needs file-scope behavior, provide a virtual path:

```go
findings, err := scanner.ScanDocument(ctx, promptinel.Document{
	Path:    "docs/prompt.md",
	Content: promptText,
})
```

This allows config scopes such as `docs/**` to apply to the in-memory scan.

If the content comes from a real file and path-aware rules need the filesystem
location, pass both values:

```go
findings, err := scanner.ScanDocument(ctx, promptinel.Document{
	Path:         "skills/demo/SKILL.md",
	AbsolutePath: "/repo/skills/demo/SKILL.md",
	Content:      promptText,
})
```

Keep `Document.Path` relative to the logical location you want Promptinel to
match against. Put the absolute filesystem location in
`Document.AbsolutePath`.

If you do not need scopes, use `Scan` instead.

## Config

The library does not auto-discover config files. Create a config explicitly and
modify it in code before building the scanner.

```go
cfg := promptinel.NewConfig()
cfg.Policy.WarnOn = promptinel.SeverityHigh
cfg.CustomRules = []promptinel.CustomRule{
	{
		ID:       "blocked-domain",
		Pattern:  "evilcorp\\.example",
		Severity: promptinel.SeverityHigh,
		Message:  "disallowed external domain referenced in prompt",
	},
}

scanner, err := promptinel.NewScanner(cfg)
```

## Special Finding IDs

The package re-exports these IDs for callers that want to handle skip findings
explicitly:

- `promptinel.OversizedFileSkipID`
- `promptinel.UnreadableFileSkipID`
