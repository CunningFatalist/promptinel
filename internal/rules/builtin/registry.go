package builtin

import (
	"fmt"

	"github.com/CunningFatalist/promptinel/internal/rules"
	nobidicontrolcharacters "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_bidi_control_characters"
	nocommandchaining "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_command_chaining"
	nocurlpipeshell "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_curl_pipe_shell"
	nodatauripayloads "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_data_uri_payloads"
	nodnsexfiltration "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_dns_exfiltration"
	nodownloadexecute "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_download_execute"
	nogitconfigcredentialhelper "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_gitconfig_credential_helper"
	nohiddenhtmlinstructions "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_hidden_html_instructions"
	noinsecurehttp "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_insecure_http"
	nointerpreterinlineexec "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_interpreter_inline_exec"
	nometadataserviceaccess "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_metadata_service_access"
	nomixedscriptidentifiers "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_mixed_script_identifiers"
	nooverridecapabilityflow "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_override_capability_flow"
	nopowershelldownloadcradle "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_powershell_download_cradle"
	nopromptinjectionoverride "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_prompt_injection_override"
	noroleheaderspoofing "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_role_header_spoofing"
	nosecretexfiltrationintent "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_secret_exfiltration_intent"
	nosecrettonetworkflow "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_secret_to_network_flow"
	nosensitivefilepaths "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_sensitive_file_paths"
	noshellheredocpayload "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_shell_heredoc_payload"
	noshellprofilemodification "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_shell_profile_modification"
	nosshconfigmanipulation "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_ssh_config_manipulation"
	nostageddownloadexecution "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_staged_download_execution"
	nosuspiciousbase64 "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_suspicious_base64"
	notaintedplaceholderinstructions "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_tainted_placeholder_instructions"
	notemplatenetworkfetch "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_template_network_fetch"
	notranscriptinjection "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_transcript_injection"
	notunnelandreverseshell "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_tunnel_and_reverse_shell"
	nounsafetemplates "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_unsafe_templates"
	nourlencodedcommandpayload "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_url_encoded_command_payload"
	nowebhookexfiltration "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_webhook_exfiltration"
	noyamljsonrolefields "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_yaml_json_role_fields"
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
		nodnsexfiltration.New(),
		nodownloadexecute.New(),
		nogitconfigcredentialhelper.New(),
		nohiddenhtmlinstructions.New(),
		noinsecurehttp.New(),
		nointerpreterinlineexec.New(),
		nometadataserviceaccess.New(),
		nomixedscriptidentifiers.New(),
		nooverridecapabilityflow.New(),
		nopowershelldownloadcradle.New(),
		nopromptinjectionoverride.New(),
		noroleheaderspoofing.New(),
		nosecretexfiltrationintent.New(),
		nosecrettonetworkflow.New(),
		nosensitivefilepaths.New(),
		noshellheredocpayload.New(),
		noshellprofilemodification.New(),
		nosshconfigmanipulation.New(),
		nostageddownloadexecution.New(),
		nosuspiciousbase64.New(),
		notaintedplaceholderinstructions.New(),
		notemplatenetworkfetch.New(),
		notranscriptinjection.New(),
		notunnelandreverseshell.New(),
		nounsafetemplates.New(),
		nourlencodedcommandpayload.New(),
		nowebhookexfiltration.New(),
		noyamljsonrolefields.New(),
		nozerowidth.New(),
	}

	for _, rule := range ruleSet {
		if err := registry.Register(rule); err != nil {
			return nil, fmt.Errorf("register rule %q: %w", rule.Metadata().ID, err)
		}
	}

	return registry, nil
}
