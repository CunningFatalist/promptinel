package version

import (
	"runtime/debug"
	"testing"
)

func Test_Version_EffectiveFromBuildInfo_PrefersMainModuleVersion(t *testing.T) {
	t.Parallel()

	buildInfo := &debug.BuildInfo{
		Main: debug.Module{
			Path:    modulePath,
			Version: "v1.2.3",
		},
		Deps: []*debug.Module{{
			Path:    modulePath,
			Version: "v9.9.9",
		}},
	}

	if actual := effectiveFromBuildInfo(buildInfo); actual != "v1.2.3" {
		t.Fatalf("expected main module version, got %q", actual)
	}
}

func Test_Version_EffectiveFromBuildInfo_UsesDependencyVersionForLibraryConsumers(t *testing.T) {
	t.Parallel()

	buildInfo := &debug.BuildInfo{
		Main: debug.Module{
			Path:    "example.com/consumer",
			Version: "v0.1.0",
		},
		Deps: []*debug.Module{{
			Path:    modulePath,
			Version: "v1.2.3",
		}},
	}

	if actual := effectiveFromBuildInfo(buildInfo); actual != "v1.2.3" {
		t.Fatalf("expected dependency version, got %q", actual)
	}
}

func Test_Version_EffectiveFromBuildInfo_FallsBackToDevelopment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		buildInfo *debug.BuildInfo
	}{
		{name: "nil build info"},
		{
			name: "missing promptinel module",
			buildInfo: &debug.BuildInfo{
				Main: debug.Module{
					Path:    "example.com/consumer",
					Version: "v0.1.0",
				},
			},
		},
		{
			name: "devel main module",
			buildInfo: &debug.BuildInfo{
				Main: debug.Module{
					Path:    modulePath,
					Version: "(devel)",
				},
			},
		},
		{
			name: "empty dependency version",
			buildInfo: &debug.BuildInfo{
				Main: debug.Module{
					Path:    "example.com/consumer",
					Version: "v0.1.0",
				},
				Deps: []*debug.Module{{
					Path: modulePath,
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if actual := effectiveFromBuildInfo(tt.buildInfo); actual != Development {
				t.Fatalf("expected development version, got %q", actual)
			}
		})
	}
}

func Test_Version_Display_PrefixesReleaseVersions(t *testing.T) {
	t.Parallel()

	previousBuildVersion := BuildVersion
	BuildVersion = "1.2.3"
	t.Cleanup(func() {
		BuildVersion = previousBuildVersion
	})

	if actual := Display(); actual != "v1.2.3" {
		t.Fatalf("expected v-prefixed version, got %q", actual)
	}
}
