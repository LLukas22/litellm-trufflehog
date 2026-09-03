package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// catchAllType is the DetectorType our catch-all reports under; findings are
// filtered by it so that a provider detector firing cannot mask a result here.
const catchAllType = "CustomRegex"

func newCatchAllScanner(t *testing.T) *Scanner {
	t.Helper()
	return newTestScanner(t, Config{
		Profile:          ProfileMinimal,
		IncludeDetectors: []string{catchAllSelector},
	})
}

func catchAllHits(r Report) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.DetectorType == catchAllType {
			out = append(out, f)
		}
	}
	return out
}

// The point of the detector: credentials with no issuer-identifying shape, which
// no provider detector can recognise. The base64-shaped case is exactly what
// trufflehog's Generic detector throws away.
func TestCatchAllFindsUnbrandedSecrets(t *testing.T) {
	s := newCatchAllScanner(t)

	for _, tc := range []struct{ name, payload, want string }{
		{"base64-shaped token", "SCIM_TOKEN: " + fakeBase64ShapedSecret, fakeBase64ShapedSecret},
		{"hyphenated key", "SEARCH_API_KEY: " + fakeUnbrandedSecret, fakeUnbrandedSecret},
		{"quoted value", `client_secret: "` + fakeUnbrandedSecret + `"`, fakeUnbrandedSecret},
		{"shell default", "${SCIM_TOKEN:-" + fakeUnbrandedSecret + "}", fakeUnbrandedSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.payload)
			report := s.Scan(context.Background(), data)
			if len(catchAllHits(report)) == 0 {
				t.Fatalf("expected a finding in %q", tc.payload)
			}

			// Containment, not equality: the window regex can pull in adjacent
			// punctuation ("${VAR:-secret}" yields ":-secret"), which still
			// removes the secret. What matters is that no part of it survives.
			covered := spanTexts(report, catchAllType, data)
			for _, got := range covered {
				if strings.Contains(got, tc.want) {
					return
				}
			}
			t.Errorf("no span covered %q; spans covered %q", tc.want, covered)
		})
	}
}

// Dropping trufflehog's base64 rule would report every git SHA, checksum and
// image digest in a prompt, so the hex exclusion has to cover all digest lengths.
func TestCatchAllIgnoresDigestsAndJunk(t *testing.T) {
	s := newCatchAllScanner(t)

	for _, tc := range []struct{ name, payload string }{
		{"md5", "cache_key: 9e107d9d372bb6826bd81d3542a419d6"},
		{"sha1", "GIT_COMMIT_TOKEN_REF: 2aabfe228f219e9cb0eb53f16947ccf25ec84d8d"},
		{"sha256", "SECRET_CHECKSUM: " + strings.Repeat("ab12cd34", 8)},
		{"image digest", "image: registry/app@sha256:" + strings.Repeat("9f86d081", 8)},
		{"uuid", "client_secret: " + fakeUUID},
		{"repeated padding", "TOKEN_PLACEHOLDER: aaaa1111aaaa1111"},
		{"zeroes", "api_key_id: 0000000000000000"},
		{"file path", "key_file: /etc/ssl/private/service-account-key.pem"},
		{"url", "token_endpoint: https://login.microsoftonline.com/common/oauth2"},
		{"dictionary words", "POSTGRES_PASSWORD: postgres_password_placeholder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := s.Scan(context.Background(), []byte(tc.payload))
			if hits := catchAllHits(report); len(hits) != 0 {
				t.Errorf("false positive in %q: %d findings", tc.payload, len(hits))
			}
		})
	}
}

// Prose that merely talks about credentials trips the keyword prefilter but must
// not produce findings, or the profile is unusable on real prompts.
func TestCatchAllIgnoresCredentialProse(t *testing.T) {
	s := newCatchAllScanner(t)

	for _, payload := range []string{
		"Please rotate the password and the client_secret for the service account.",
		"My API key stopped working after I regenerated the token yesterday.",
		"Store credentials in the secret manager, never in the compose file.",
		"aws_access_key_id = REDACTED\naws_secret_access_key = REDACTED",
		"the token is invalid, the password expired, and the key was revoked",
	} {
		report := s.Scan(context.Background(), []byte(payload))
		if hits := catchAllHits(report); len(hits) != 0 {
			t.Errorf("false positive in prose %q: %d findings", payload, len(hits))
		}
	}
}

// The entropy floor is what rejects padding, so its relationship to real
// credentials must stay comfortable rather than marginal.
func TestCatchAllEntropyFloorHasHeadroom(t *testing.T) {
	for _, secret := range []string{
		fakeBase64ShapedSecret, fakeUnbrandedSecret, fakeAWSSecret, fakeGitHubPAT,
	} {
		if got := detectors.StringShannonEntropy(secret); got < catchAllMinEntropy+0.5 {
			t.Errorf("entropy of %q is %.2f, uncomfortably close to the %.1f floor",
				secret, got, catchAllMinEntropy)
		}
	}
	for _, junk := range []string{"aaaa1111aaaa1111", "0000000000000000", "abababababababab"} {
		if got := detectors.StringShannonEntropy(junk); got >= catchAllMinEntropy {
			t.Errorf("entropy of %q is %.2f, the floor of %.1f will not reject it",
				junk, got, catchAllMinEntropy)
		}
	}
}

// Findings are labelled by name, since the underlying DetectorType is the shared
// CustomRegex slot and would otherwise be meaningless to a caller.
func TestCatchAllFindingIsLabelledByName(t *testing.T) {
	s := newCatchAllScanner(t)
	report := s.Scan(context.Background(), []byte("SCIM_TOKEN: "+fakeBase64ShapedSecret))

	hits := catchAllHits(report)
	if len(hits) == 0 {
		t.Fatal("expected a finding")
	}
	if hits[0].DetectorName != catchAllSelector {
		t.Errorf("DetectorName = %q, want %q", hits[0].DetectorName, catchAllSelector)
	}
	if hits[0].Description == "" {
		t.Error("expected a description explaining what this detector is")
	}
}
