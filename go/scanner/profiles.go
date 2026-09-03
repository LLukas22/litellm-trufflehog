package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Profile names accepted by Config.Profile.
const (
	ProfileMinimal  = "minimal"
	ProfileCore     = "core"
	ProfileAll      = "all"
	ProfileParanoid = "paranoid"
)

// DefaultProfile is used when Config.Profile is empty.
const DefaultProfile = ProfileCore

// minimalDetectors is the lowest-latency, lowest-false-positive set: cloud,
// source control, private keys/JWTs and LLM provider keys.
//
// Every name must match an enum value in trufflehog's proto/detector_type.proto,
// enforced by TestProfilesResolve.
var minimalDetectors = []string{
	// Cloud
	"AWS", "AWSSessionKey",
	"GCP", "GCPApplicationDefaultCredentials",
	"Azure", "AzureStorage", "AzureSasToken",
	// Source control (Gitlab covers v1/v2/v3, including OAuth2 tokens)
	"Github", "GitHubApp", "GitHubOauth2",
	"Gitlab",
	// Generic credential material
	"PrivateKey", "JWT",
	// LLM providers
	"OpenAI", "OpenAIAdmin", "Anthropic", "GoogleGeminiAPIKey", "AzureOpenAI",
	"Groq", "DeepSeek", "XAI", "HuggingFace",
	// High-impact SaaS
	"Slack", "SlackWebhook", "Stripe",
	// Registries / secret stores
	"NpmToken", "Dockerhub", "HashiCorpVaultAuth",
}

// coreExtraDetectors is layered on minimalDetectors to form the "core" profile:
// the realistic leak surface for an LLM gateway, without the long tail.
var coreExtraDetectors = []string{
	// Cloud / infrastructure
	// (Entra/AD service-principal secrets are reported by the Azure detector.)
	"AzureDevopsPersonalAccessToken", "AzureSearchAdminKey", "AzureContainerRegistry",
	"GoogleOauth2", "DigitalOceanToken", "DigitalOceanV2",
	"Heroku", "FlyIO", "Vercel", "Netlify", "RailwayApp",
	"CloudflareApiToken", "CloudflareGlobalApiKey", "CloudflareCaKey",
	"Tailscale", "Ngrok",

	// Source control / CI / package registries
	"BitbucketAppPassword", "BitbucketDataCenter",
	"PyPI", "RubyGems", "NuGetApiKey", "Docker",
	"Circle", "Buildkite", "DroneCI", "TravisCI",
	"TerraformCloudPersonalToken", "Harness", "Sourcegraph",

	// Data stores / message brokers
	"Postgres", "MongoDB", "Redis", "SQLServer", "RabbitMQ",
	"Snowflake", "Couchbase", "LDAP", "FTP", "PlanetScaleDb",
	"DatabricksToken", "JDBC", "URI",

	// AI / ML ops
	"Replicate", "ElevenLabs", "NVAPI",
	"LangSmith", "Langfuse", "WeightsAndBiases",

	// Secret management
	"Doppler", "Pulumi", "SupabaseToken",

	// Communications / payments
	"DiscordBotToken", "DiscordWebhook", "MicrosoftTeamsWebhook", "TelegramBotToken",
	"StripePaymentIntent", "Square", "SquareApp", "PaypalOauth", "Coinbase",
	"SendGrid", "Mailgun", "Mailchimp", "Postmark", "Twilio", "TwilioApiKey",

	// Identity / observability / business SaaS
	"Okta", "Auth0ManagementApiToken", "Auth0oauth", "OneLogin",
	"DatadogToken", "NewRelicPersonalApiKey",
	"Grafana", "GrafanaServiceAccount", "SentryToken", "SentryOrgToken",
	"Notion", "LinearAPI", "JiraToken", "JiraDataCenterPAT",
	"AsanaPersonalAccessToken", "Shopify", "ShopifyOAuth",
	"Salesforce", "SalesforceRefreshToken", "FigmaPersonalAccessToken",
}

// profileNames returns the detector names making up a named profile.
//
// Neither catch-all detector is ever enabled implicitly. Both match any 16-64
// printable characters near the words pass/token/cred/secret/key, which makes
// them the largest source of false positives, and their matches often cover the
// key name or trailing punctuation rather than just the value - so pair them with
// a blocking or logging policy rather than redaction.
//
//   - "HighEntropy" is ours (see catchall.go) and the one "paranoid" enables.
//   - "Generic" is trufflehog's, reachable only by naming it in IncludeDetectors.
//     It is kept unchanged, blind spot included: it discards any candidate that
//     base64-decodes, so a value that happens to be a multiple of four characters
//     from the base64 alphabet stays invisible to it.
func profileNames(profile string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "":
		return profileNames(DefaultProfile)
	case ProfileMinimal:
		return append([]string(nil), minimalDetectors...), nil
	case ProfileCore:
		out := make([]string, 0, len(minimalDetectors)+len(coreExtraDetectors))
		out = append(out, minimalDetectors...)
		out = append(out, coreExtraDetectors...)
		return out, nil
	case ProfileAll:
		// "all" is a special group understood by trufflehog's detector parser.
		return []string{ProfileAll}, nil
	case ProfileParanoid:
		// Everything, plus our catch-all. Not trufflehog's Generic: the two
		// overlap almost entirely, so enabling both would report most secrets
		// twice while re-introducing the base64 blind spot for the rest.
		return []string{ProfileAll, catchAllSelector}, nil
	default:
		return nil, fmt.Errorf("unknown profile %q (want one of: %s)",
			profile, strings.Join(Profiles(), ", "))
	}
}

// Profiles returns the supported profile names, sorted.
func Profiles() []string {
	p := []string{ProfileAll, ProfileCore, ProfileMinimal, ProfileParanoid}
	sort.Strings(p)
	return p
}
