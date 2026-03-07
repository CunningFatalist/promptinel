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
	nohiddendirectionality "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_hidden_directionality"
	nohiddenhtmlinstructions "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_hidden_html_instructions"
	noinsecurehttp "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_insecure_http"
	nointerpreterinlineexec "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_interpreter_inline_exec"
	nometadataserviceaccess "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_metadata_service_access"
	nomixedscriptidentifiers "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_mixed_script_identifiers"
	nomultilayerencoding "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_multilayer_encoding"
	nononstandardwhitespace "github.com/CunningFatalist/promptinel/internal/rules/builtin/no_nonstandard_whitespace"
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
	skillhasbundledresources "github.com/CunningFatalist/promptinel/internal/rules/builtin/skill_has_bundled_resources"
)

type documentedRule struct {
	rules.Rule
	docsFile string
}

func (r documentedRule) Metadata() rules.Metadata {
	meta := r.Rule.Metadata()
	meta.DocsFile = r.docsFile
	return meta
}

func (r documentedRule) CheckDocument(ctx rules.Context, doc rules.DocumentView) []rules.Finding {
	documentRule, ok := r.Rule.(rules.DocumentRule)
	if !ok {
		return nil
	}

	return documentRule.CheckDocument(ctx, doc)
}

func (r documentedRule) CheckSegment(ctx rules.Context, segment rules.Segment) []rules.Finding {
	segmentRule, ok := r.Rule.(rules.SegmentRule)
	if !ok {
		return nil
	}

	return segmentRule.CheckSegment(ctx, segment)
}

func (r documentedRule) CheckTokens(ctx rules.Context, segment rules.Segment, tokens []rules.Token) []rules.Finding {
	tokenRule, ok := r.Rule.(rules.TokenRule)
	if !ok {
		return nil
	}

	return tokenRule.CheckTokens(ctx, segment, tokens)
}

func (r documentedRule) CheckFlow(ctx rules.Context, doc rules.AnalyzedDocument) []rules.Finding {
	flowRule, ok := r.Rule.(rules.FlowRule)
	if !ok {
		return nil
	}

	return flowRule.CheckFlow(ctx, doc)
}

// NewRegistry returns the registry containing built-in rules.
func NewRegistry() (*rules.Registry, error) {
	registry := rules.NewRegistry()

	ruleSet := []documentedRule{
		{Rule: nobidicontrolcharacters.New(), docsFile: "NoBidiControlCharacters.md"},
		{Rule: nocommandchaining.New(), docsFile: "NoCommandChaining.md"},
		{Rule: nocurlpipeshell.New(), docsFile: "NoCurlPipeShell.md"},
		{Rule: nodatauripayloads.New(), docsFile: "NoDataUriPayloads.md"},
		{Rule: nodnsexfiltration.New(), docsFile: "NoDnsExfiltration.md"},
		{Rule: nodownloadexecute.New(), docsFile: "NoDownloadExecute.md"},
		{Rule: nogitconfigcredentialhelper.New(), docsFile: "NoGitconfigCredentialHelper.md"},
		{Rule: nohiddendirectionality.New(), docsFile: "NoHiddenDirectionality.md"},
		{Rule: nohiddenhtmlinstructions.New(), docsFile: "NoHiddenHtmlInstructions.md"},
		{Rule: noinsecurehttp.New(), docsFile: "NoInsecureHttp.md"},
		{Rule: nointerpreterinlineexec.New(), docsFile: "NoInterpreterInlineExec.md"},
		{Rule: nometadataserviceaccess.New(), docsFile: "NoMetadataServiceAccess.md"},
		{Rule: nomixedscriptidentifiers.New(), docsFile: "NoMixedScriptIdentifiers.md"},
		{Rule: nomultilayerencoding.New(), docsFile: "NoMultilayerEncoding.md"},
		{Rule: nononstandardwhitespace.New(), docsFile: "NoNonstandardWhitespace.md"},
		{Rule: nooverridecapabilityflow.New(), docsFile: "NoOverrideCapabilityFlow.md"},
		{Rule: nopowershelldownloadcradle.New(), docsFile: "NoPowershellDownloadCradle.md"},
		{Rule: nopromptinjectionoverride.New(), docsFile: "NoPromptInjectionOverride.md"},
		{Rule: noroleheaderspoofing.New(), docsFile: "NoRoleHeaderSpoofing.md"},
		{Rule: nosecretexfiltrationintent.New(), docsFile: "NoSecretExfiltrationIntent.md"},
		{Rule: nosecrettonetworkflow.New(), docsFile: "NoSecretToNetworkFlow.md"},
		{Rule: nosensitivefilepaths.New(), docsFile: "NoSensitiveFilePaths.md"},
		{Rule: noshellheredocpayload.New(), docsFile: "NoShellHeredocPayload.md"},
		{Rule: noshellprofilemodification.New(), docsFile: "NoShellProfileModification.md"},
		{Rule: nosshconfigmanipulation.New(), docsFile: "NoSshConfigManipulation.md"},
		{Rule: skillhasbundledresources.New(), docsFile: "SkillHasBundledResources.md"},
		{Rule: nostageddownloadexecution.New(), docsFile: "NoStagedDownloadExecution.md"},
		{Rule: nosuspiciousbase64.New(), docsFile: "NoSuspiciousBase64.md"},
		{Rule: notaintedplaceholderinstructions.New(), docsFile: "NoTaintedPlaceholderInstructions.md"},
		{Rule: notemplatenetworkfetch.New(), docsFile: "NoTemplateNetworkFetch.md"},
		{Rule: notranscriptinjection.New(), docsFile: "NoTranscriptInjection.md"},
		{Rule: notunnelandreverseshell.New(), docsFile: "NoTunnelAndReverseShell.md"},
		{Rule: nounsafetemplates.New(), docsFile: "NoUnsafeTemplates.md"},
		{Rule: nourlencodedcommandpayload.New(), docsFile: "NoUrlEncodedCommandPayload.md"},
		{Rule: nowebhookexfiltration.New(), docsFile: "NoWebhookExfiltration.md"},
		{Rule: noyamljsonrolefields.New(), docsFile: "NoYamlJsonRoleFields.md"},
		{Rule: nozerowidth.New(), docsFile: "NoZeroWidth.md"},
	}

	for _, rule := range ruleSet {
		if err := registry.Register(rule); err != nil {
			return nil, fmt.Errorf("register rule %q: %w", rule.Metadata().ID, err)
		}
	}

	return registry, nil
}
