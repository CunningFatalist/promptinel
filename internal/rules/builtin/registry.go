package builtin

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/rules"
	nobidicontrolcharacters "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_bidi_control_characters"
	nocommandchaining "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_command_chaining"
	nocurlpipeshell "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_curl_pipe_shell"
	nodatauripayloads "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_data_uri_payloads"
	nodownloadexecute "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_download_execute"
	nohiddenhtmlinstructions "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_hidden_html_instructions"
	noinsecurehttp "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_insecure_http"
	nometadataserviceaccess "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_metadata_service_access"
	nooverridecapabilityflow "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_override_capability_flow"
	nopromptinjectionoverride "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_prompt_injection_override"
	nosecretexfiltrationintent "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_secret_exfiltration_intent"
	nosecrettonetworkflow "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_secret_to_network_flow"
	nosensitivefilepaths "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_sensitive_file_paths"
	nostageddownloadexecution "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_staged_download_execution"
	nosuspiciousbase64 "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_suspicious_base64"
	nounsafetemplates "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_unsafe_templates"
	nozerowidth "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_zero_width"
)

// NewRegistry returns the registry containing built-in rules.
func NewRegistry() (*rules.Registry, error) {
	registry := rules.NewRegistry()

	ruleSet := []rules.Rule{
		nobidicontrolcharacters.New(),
		nocommandchaining.New(),
		nocurlpipeshell.New(),
		nodatauripayloads.New(),
		nodownloadexecute.New(),
		nohiddenhtmlinstructions.New(),
		noinsecurehttp.New(),
		nometadataserviceaccess.New(),
		nooverridecapabilityflow.New(),
		nopromptinjectionoverride.New(),
		nosecretexfiltrationintent.New(),
		nosecrettonetworkflow.New(),
		nosensitivefilepaths.New(),
		nostageddownloadexecution.New(),
		nosuspiciousbase64.New(),
		nozerowidth.New(),
		nounsafetemplates.New(),
	}

	for _, rule := range ruleSet {
		if err := registry.Register(rule); err != nil {
			return nil, fmt.Errorf("register rule %q: %w", rule.Metadata().ID, err)
		}
	}

	return registry, nil
}
