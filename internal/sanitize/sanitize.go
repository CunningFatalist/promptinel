package sanitize

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/CunningFatalist/promptinel/internal/config"
	"github.com/CunningFatalist/promptinel/internal/files"
	"github.com/CunningFatalist/promptinel/internal/filters"
	"github.com/CunningFatalist/promptinel/internal/normalize"
	"github.com/CunningFatalist/promptinel/internal/safefile"
)

// Request configures sanitize execution.
type Request struct {
	Paths      []string
	ConfigFile string
	Discover   bool
	Include    []string
	Exclude    []string
	IncludeSet bool
	ExcludeSet bool
	Apply      bool
}

// Action describes the per-file sanitize outcome.
type Action string

const (
	ActionSkipped       Action = "skipped"
	ActionWouldSanitize Action = "would_sanitize"
	ActionSanitized     Action = "sanitized"
)

var writeFileAtomically = safefile.WriteFileAtomically

// Event captures one emitted sanitize operation entry.
type Event struct {
	Path                   string
	Action                 Action
	Reason                 string
	LineEndingsNormalized  int
	ZeroWidthRunesStripped int
}

// Summary aggregates sanitize execution metrics.
type Summary struct {
	Files                  int
	Changed                int
	Skipped                int
	LineEndingsNormalized  int
	ZeroWidthRunesStripped int
	Applied                bool
}

// Result contains emitted events and summary metrics.
type Result struct {
	Events  []Event
	Summary Summary
}

// Run executes sanitize workflow.
func Run(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	cfg, err := config.LoadWithOptions(req.ConfigFile, config.LoadOptions{Discover: req.Discover})
	if err != nil {
		return Result{}, fmt.Errorf("load config: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	includes, excludes := filters.ResolveEffective(cfg, req.Include, req.Exclude, req.IncludeSet, req.ExcludeSet)
	targets, skippedDuringDiscovery, err := files.CollectTargets(req.Paths, files.SanitizeCollectOptions(), includes, excludes)
	if err != nil {
		return Result{}, fmt.Errorf("collect files: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	result := Result{Events: make([]Event, 0, len(targets)+len(skippedDuringDiscovery))}
	for _, skipped := range skippedDuringDiscovery {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		result.Events = append(result.Events, Event{Path: skipped.RelativePath, Action: ActionSkipped, Reason: skipped.Reason})
		result.Summary.Skipped++
	}

	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		info, statErr := os.Lstat(target.AbsolutePath)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: "path no longer exists"})
				result.Summary.Skipped++
				continue
			}
			return Result{}, fmt.Errorf("lstat file %q: %w", target.AbsolutePath, statErr)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: "symbolic links are not sanitized"})
			result.Summary.Skipped++
			continue
		}
		if !info.Mode().IsRegular() {
			result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: "non-regular file"})
			result.Summary.Skipped++
			continue
		}

		if info.Size() > cfg.Limits.MaxFileSizeBytes {
			result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: fmt.Sprintf("size %d exceeds limits.max_file_size_bytes=%d", info.Size(), cfg.Limits.MaxFileSizeBytes)})
			result.Summary.Skipped++
			continue
		}

		content, readErr := os.ReadFile(target.AbsolutePath)
		if readErr != nil {
			result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: fmt.Sprintf("read error: %v", readErr)})
			result.Summary.Skipped++
			continue
		}

		normalized := normalize.ForSanitize(string(content))
		if normalized.Content == string(content) {
			continue
		}

		result.Summary.Changed++
		result.Summary.LineEndingsNormalized += normalized.LineEndingsNormalized
		result.Summary.ZeroWidthRunesStripped += normalized.ZeroWidthRunesStripped

		action := ActionWouldSanitize
		if req.Apply {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}

			latestInfo, latestErr := os.Lstat(target.AbsolutePath)
			if latestErr != nil {
				if errors.Is(latestErr, os.ErrNotExist) {
					result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: "path no longer exists"})
					result.Summary.Skipped++
					continue
				}
				return Result{}, fmt.Errorf("lstat file before write %q: %w", target.AbsolutePath, latestErr)
			}
			if latestInfo.Mode()&os.ModeSymlink != 0 {
				result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: "symbolic links are not sanitized"})
				result.Summary.Skipped++
				continue
			}
			if !latestInfo.Mode().IsRegular() {
				result.Events = append(result.Events, Event{Path: target.RelativePath, Action: ActionSkipped, Reason: "non-regular file"})
				result.Summary.Skipped++
				continue
			}
			if err := writeFileAtomically(target.AbsolutePath, []byte(normalized.Content), info.Mode().Perm(), safefile.AtomicWriteOptions{
				TempPattern: ".promptinel-sanitize-*",
			}); err != nil {
				return Result{}, fmt.Errorf("write sanitized file %q: %w", target.AbsolutePath, err)
			}
			action = ActionSanitized
		}

		result.Events = append(result.Events, Event{
			Path:                   target.RelativePath,
			Action:                 action,
			LineEndingsNormalized:  normalized.LineEndingsNormalized,
			ZeroWidthRunesStripped: normalized.ZeroWidthRunesStripped,
		})
	}

	result.Summary.Files = len(targets)
	result.Summary.Applied = req.Apply
	return result, nil
}
