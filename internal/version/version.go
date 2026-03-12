package version

import (
	"runtime/debug"
	"strings"
)

const (
	// Development marks local or unresolved builds.
	Development = "development"
	modulePath  = "github.com/CunningFatalist/promptinel"
)

// BuildVersion is the Promptinel version embedded at build time.
var BuildVersion = Development

// Effective returns the resolved Promptinel version without display formatting.
func Effective() string {
	if BuildVersion != Development {
		return BuildVersion
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return Development
	}

	return effectiveFromBuildInfo(buildInfo)
}

// Display returns the resolved Promptinel version formatted for users.
func Display() string {
	version := Effective()
	if version == Development {
		return version
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func effectiveFromBuildInfo(buildInfo *debug.BuildInfo) string {
	if buildInfo == nil {
		return Development
	}

	if buildInfo.Main.Path == modulePath {
		return normalizeGoVersion(buildInfo.Main.Version)
	}

	for _, dep := range buildInfo.Deps {
		if dep == nil || dep.Path != modulePath {
			continue
		}
		return normalizeGoVersion(dep.Version)
	}

	return Development
}

func normalizeGoVersion(version string) string {
	if version == "" || version == "(devel)" {
		return Development
	}
	return version
}
