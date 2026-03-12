package promptinel

import internalversion "github.com/CunningFatalist/promptinel/internal/version"

// Version returns the resolved Promptinel version for the current build.
func Version() string {
	return internalversion.Display()
}
