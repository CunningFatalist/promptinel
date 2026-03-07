package ruledocs

import "path"

const (
	RepoBaseURL   = "https://github.com/CunningFatalist/promptinel"
	RulesDir      = "docs/rules"
	CustomDocFile = "Custom.md"

	rulesBlobBaseURL = RepoBaseURL + "/blob/main/" + RulesDir
)

// Path returns the repository-relative path to a rule documentation file.
func Path(file string) string {
	if file == "" {
		return ""
	}

	return path.Join(RulesDir, file)
}

// URL returns the GitHub URL to a rule documentation file.
func URL(file string) string {
	if file == "" {
		return ""
	}

	return rulesBlobBaseURL + "/" + file
}
