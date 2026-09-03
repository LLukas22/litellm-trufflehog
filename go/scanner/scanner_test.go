package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// Synthetic credentials, none real. They satisfy each detector's regex and also
// survive trufflehog's false-positive filters, which reject unverified secrets
// containing a DefaultFalsePositives term ("example", "abcde", ...) or a
// dictionary word - so AWS's published "EXAMPLE" keys are unusable here.
const (
	// idPat: (?:AKIA|ABIA|ACCA)[A-Z0-9]{16}
	fakeAWSKeyID = "AKIAQRSTUV234567WXYZ"
	// aws.SecretPat: [A-Za-z0-9+/]{40}, and must not look like a hex digest
	// (FalsePositiveSecretPat) or it is dropped when unverified.
	fakeAWSSecret = "Xk8Qm2vN7pL5rT9wYb3dF6hJ1sA4gK0zC8nMxQ2e"

	// keyPat: sk-(?:...|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+
	fakeOpenAIKey = "sk-Qm7Xk2Vp9Rt4T3BlbkFJLs6Wn3Zy8Hq5Jd7Fg2Kv4Mb"

	// keyPat: (?:ghp|gho|...)_[a-zA-Z0-9_]{36,255}
	fakeGitHubPAT = "ghp_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5"

	// xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*
	fakeSlackBotToken = "xoxb-1234567890123-1234567890123-Qm7Xk2Vp9Rt4Ls6Wn3Zy8Hq5"

	// A credential with no issuer-identifying shape, as an internal service or a
	// proxy hands out: invisible to every provider detector, so only a catch-all
	// can find it. The hyphens matter - they keep it from decoding as base64,
	// which trufflehog's Generic detector silently discards.
	fakeUnbrandedSecret = "DlhsHVp-y4qvxL1-koFlber-pMeUMdB"

	// The same kind of credential, but 28 characters from the base64 alphabet, so
	// it decodes cleanly and Generic throws it away. Pins that blind spot.
	fakeBase64ShapedSecret = "1uFtpdS8i8mdY7kq6eetrrBEvOrM"

	// A database password, for connection-string fixtures. Kept separate from the
	// AWS fixtures so a test asserting on connection-string parts cannot be
	// confused about which credential a span belongs to.
	fakeDBPassword = "iyHlOSsmrVRmHAfRpfPlmKHW"

	// A UUID, which every catch-all must reject. Random, not from any real tenant.
	fakeUUID = "8cd69905-409f-459e-ba39-1d5cb354af48"
)

// fakeAnthropicKey satisfies sk-ant-api03-[\w\-]{93}AA.
var fakeAnthropicKey = "sk-ant-api03-" + strings.Repeat("a1B2c3D4e5", 9) + "abc" + "AA"

func newTestScanner(t *testing.T, cfg Config) *Scanner {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func detectorTypes(r Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.DetectorType)
	}
	return out
}

func hasDetector(r Report, want string) bool {
	for _, f := range r.Findings {
		if f.DetectorType == want {
			return true
		}
	}
	return false
}

// spanTexts returns the input covered by every span one detector reported, which
// is exactly what redaction would mask.
func spanTexts(r Report, detector string, data []byte) []string {
	var out []string
	for _, f := range r.Findings {
		if f.DetectorType != detector {
			continue
		}
		for _, sp := range f.Spans {
			out = append(out, string(data[sp.Start:sp.End]))
		}
	}
	return out
}

func TestScanDetectsCoreProfileSecrets(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileCore})

	cases := []struct {
		name  string
		text  string
		want  string
		spans []string // fragments that must be covered by the finding's spans
	}{
		{
			name:  "aws access key",
			text:  "aws_access_key_id = " + fakeAWSKeyID + "\naws_secret_access_key = " + fakeAWSSecret + "\n",
			want:  "AWS",
			spans: []string{fakeAWSKeyID, fakeAWSSecret},
		},
		{
			name:  "openai key",
			text:  "here is my openai key: " + fakeOpenAIKey + " please use it",
			want:  "OpenAI",
			spans: []string{fakeOpenAIKey},
		},
		{
			name:  "github pat",
			text:  "clone with github token " + fakeGitHubPAT,
			want:  "Github",
			spans: []string{fakeGitHubPAT},
		},
		{
			name:  "slack bot token",
			text:  "slack integration uses " + fakeSlackBotToken,
			want:  "Slack",
			spans: []string{fakeSlackBotToken},
		},
		{
			name:  "anthropic key",
			text:  "ANTHROPIC_API_KEY=" + fakeAnthropicKey,
			want:  "Anthropic",
			spans: []string{fakeAnthropicKey},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := s.Scan(context.Background(), []byte(tc.text))
			if !hasDetector(report, tc.want) {
				t.Fatalf("expected detector %q, got %v (errors: %v)",
					tc.want, detectorTypes(report), report.Errors)
			}

			// Every fragment expected to be maskable must be covered by a span.
			covered := map[string]bool{}
			for _, f := range report.Findings {
				if f.DetectorType != tc.want {
					continue
				}
				for _, sp := range f.Spans {
					if sp.Start < 0 || sp.End > len(tc.text) || sp.Start >= sp.End {
						t.Fatalf("span %+v out of range for input of len %d", sp, len(tc.text))
					}
					covered[tc.text[sp.Start:sp.End]] = true
				}
			}
			for _, want := range tc.spans {
				if !covered[want] {
					t.Errorf("no span covers %q; spans covered: %v", want, keys(covered))
				}
			}
		})
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Ordinary prose, including text that merely mentions providers, must not match.
func TestScanCleanTextHasNoFindings(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileCore})

	for _, text := range []string{
		"",
		"What is the capital of France?",
		"Please write a Python function that reverses a string.",
		"I use AWS and GitHub and OpenAI every day, but I will not paste keys.",
		"aws_access_key_id = REDACTED\naws_secret_access_key = REDACTED",
	} {
		report := s.Scan(context.Background(), []byte(text))
		if len(report.Findings) != 0 {
			t.Errorf("text %q: expected no findings, got %v", text, detectorTypes(report))
		}
	}
}

// data[Start:End] must be exactly the credential fragment, which is what makes
// byte-offset redaction possible on the Python side.
func TestSpansAreExactByteOffsets(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileMinimal})
	// Non-ASCII prefix: offsets are byte, not rune, offsets.
	text := "关于我的密钥 🔑 " + fakeGitHubPAT + " 结束"
	data := []byte(text)

	report := s.Scan(context.Background(), data)
	if !hasDetector(report, "Github") {
		t.Fatalf("expected Github finding, got %v", detectorTypes(report))
	}
	for _, f := range report.Findings {
		if f.DetectorType != "Github" {
			continue
		}
		if len(f.Spans) == 0 {
			t.Fatal("expected at least one span")
		}
		for _, sp := range f.Spans {
			if got := string(data[sp.Start:sp.End]); got != fakeGitHubPAT {
				t.Errorf("span %+v extracted %q, want %q", sp, got, fakeGitHubPAT)
			}
		}
	}
}

// Two occurrences need two spans, or redaction leaves the second copy in place.
func TestRepeatedSecretGetsDistinctSpans(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileMinimal})
	text := "first " + fakeGitHubPAT + " and again " + fakeGitHubPAT + " done"

	report := s.Scan(context.Background(), []byte(text))

	var starts []int
	for _, f := range report.Findings {
		if f.DetectorType != "Github" {
			continue
		}
		for _, sp := range f.Spans {
			starts = append(starts, sp.Start)
		}
	}
	if len(starts) < 2 {
		t.Fatalf("expected >=2 spans for a secret appearing twice, got %v", starts)
	}
	if starts[0] == starts[1] {
		t.Errorf("expected distinct span starts, got %v", starts)
	}
}

// Several detectors deduplicate identical results internally - OpenAI does - so
// spans must come from what the text contains, not from how many results came
// back. Otherwise redaction masks the first copy and ships the second.
func TestSpansCoverDeduplicatedRepeatedSecret(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileMinimal})
	text := "OPENAI_API_KEY: " + fakeOpenAIKey + "\nCOPY_OF_THE_SAME: " + fakeOpenAIKey + "\n"
	data := []byte(text)

	report := s.Scan(context.Background(), data)
	covered := spanTexts(report, "OpenAI", data)

	var hits int
	for _, got := range covered {
		if got == fakeOpenAIKey {
			hits++
		}
	}
	if hits != 2 {
		t.Errorf("expected both copies of the key to be spanned, got %d of 2 (%q)",
			hits, covered)
	}
}

// The same, for a part that only exists inside RawV2: AWS reports Raw=<key id>
// and RawV2=<key id>:<secret access key>, so the secret is never a whole value.
func TestSpansCoverRepeatedMultipartPart(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileMinimal})
	text := "id=" + fakeAWSKeyID + "\nsecret=" + fakeAWSSecret +
		"\nbackup_secret=" + fakeAWSSecret + "\n"
	data := []byte(text)

	report := s.Scan(context.Background(), data)
	covered := spanTexts(report, "AWS", data)

	var secrets int
	for _, got := range covered {
		if got == fakeAWSSecret {
			secrets++
		}
	}
	if secrets != 2 {
		t.Errorf("expected both copies of the secret access key to be spanned, "+
			"got %d of 2 (%q)", secrets, covered)
	}
}

// The counterweight: short RawV2 fragments are hosts, ports and database names,
// and masking every occurrence of those would mangle ordinary text.
func TestShortFragmentsAreNotMaskedEverywhere(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileCore})
	const prose = "\nnote: postgresql on port 5432 at db-primary as admin\n"
	text := "DB: postgresql://admin:" + fakeDBPassword + "@db-primary:5432/appdb" + prose
	data := []byte(text)
	proseAt := strings.Index(text, prose)

	report := s.Scan(context.Background(), data)
	if !hasDetector(report, "Postgres") {
		t.Skipf("Postgres detector did not fire; nothing to assert (%v)", detectorTypes(report))
	}
	for _, f := range report.Findings {
		for _, sp := range f.Spans {
			if sp.Start >= proseAt {
				t.Errorf("span %+v masked %q in prose after the connection string",
					sp, data[sp.Start:sp.End])
			}
		}
	}
}

func TestLocateAllFindsEveryOccurrence(t *testing.T) {
	data := []byte("xx-secret-xx-secret-xx")
	got := newOffsetTracker(data).locateAll([]byte("secret"))

	want := []Span{{Start: 3, End: 9}, {Start: 13, End: 19}}
	if len(got) != len(want) {
		t.Fatalf("locateAll returned %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("span %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLocateAllIgnoresShortAndAbsentFragments(t *testing.T) {
	tracker := newOffsetTracker([]byte("abc secret"))
	if got := tracker.locateAll([]byte("ab")); got != nil {
		t.Errorf("expected nothing below minCandidateLen, got %+v", got)
	}
	if got := tracker.locateAll([]byte("missing")); got != nil {
		t.Errorf("expected nothing for an absent fragment, got %+v", got)
	}
}

func TestCandidateSecretsFlagsSplitPartsAsFragments(t *testing.T) {
	got := candidateSecrets("", []byte(fakeAWSKeyID), []byte(fakeAWSKeyID+":"+fakeAWSSecret))

	for _, c := range got {
		switch string(c.value) {
		case fakeAWSKeyID, fakeAWSKeyID + ":" + fakeAWSSecret:
			if !c.whole {
				t.Errorf("%q is a value the detector reported, expected whole=true", c.value)
			}
		case fakeAWSSecret:
			if c.whole {
				t.Errorf("%q was split out of RawV2, expected whole=false", c.value)
			}
		}
	}
}

func TestRawWithheldUnlessRequested(t *testing.T) {
	text := "token " + fakeGitHubPAT

	s := newTestScanner(t, Config{Profile: ProfileMinimal})
	for _, f := range s.Scan(context.Background(), []byte(text)).Findings {
		if f.Raw != "" {
			t.Errorf("raw secret leaked with default config: %q", f.Raw)
		}
		if f.SecretSHA256 == "" {
			t.Error("expected SecretSHA256 to be populated")
		}
	}

	s2 := newTestScanner(t, Config{Profile: ProfileMinimal, IncludeRaw: true})
	found := false
	for _, f := range s2.Scan(context.Background(), []byte(text)).Findings {
		if f.Raw != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected raw secret when IncludeRaw is set")
	}
}

// trufflehog discards unverified results containing a placeholder term or a
// dictionary word. Usually desirable, but it can discard a genuine credential
// too, so it must remain switchable.
func TestWordlistFalsePositiveFilterIsConfigurable(t *testing.T) {
	// Contains "abcde", a member of detectors.DefaultFalsePositives.
	placeholder := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	text := []byte("github token " + placeholder)

	on := newTestScanner(t, Config{Profile: ProfileMinimal})
	if report := on.Scan(context.Background(), text); hasDetector(report, "Github") {
		t.Error("expected placeholder token to be filtered by default")
	}

	off := false
	disabled := newTestScanner(t, Config{Profile: ProfileMinimal, DropWordlistFPs: &off})
	report := disabled.Scan(context.Background(), text)
	if !hasDetector(report, "Github") {
		t.Fatalf("expected finding when filter disabled, got %v", detectorTypes(report))
	}
	for _, f := range report.Findings {
		if f.DetectorType == "Github" && !f.WordlistFalsePositive {
			t.Error("expected WordlistFalsePositive to be flagged on a retained placeholder")
		}
	}
}

func TestExcludeDetectors(t *testing.T) {
	text := "token " + fakeGitHubPAT

	s := newTestScanner(t, Config{
		Profile:          ProfileMinimal,
		ExcludeDetectors: []string{"Github"},
	})
	if report := s.Scan(context.Background(), []byte(text)); hasDetector(report, "Github") {
		t.Errorf("Github should have been excluded, got %v", detectorTypes(report))
	}
}

func TestIncludeDetectorsAddsToProfile(t *testing.T) {
	// Vercel and Notion are in core but not minimal.
	base := newTestScanner(t, Config{Profile: ProfileMinimal})
	wider := newTestScanner(t, Config{
		Profile:          ProfileMinimal,
		IncludeDetectors: []string{"Vercel", "Notion"},
	})
	if wider.DetectorCount() <= base.DetectorCount() {
		t.Errorf("expected include_detectors to widen the set: %d vs %d",
			wider.DetectorCount(), base.DetectorCount())
	}
}

func TestTruncationIsReported(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileMinimal, MaxBytes: 32})
	report := s.Scan(context.Background(), []byte(strings.Repeat("x", 100)))

	if !report.Truncated {
		t.Error("expected Truncated to be set")
	}
	if report.ScannedBytes != 32 {
		t.Errorf("ScannedBytes = %d, want 32", report.ScannedBytes)
	}
}

// A secret past MaxBytes is not scanned; Truncated is how callers learn the
// verdict is incomplete.
func TestTruncationDropsTrailingSecret(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileMinimal, MaxBytes: 16})
	report := s.Scan(context.Background(), []byte(strings.Repeat("x", 64)+fakeGitHubPAT))

	if !report.Truncated {
		t.Fatal("expected Truncated")
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected no findings from truncated input, got %v", detectorTypes(report))
	}
}

// Findings must not depend on map iteration order, or offsets would shuffle.
func TestScanIsDeterministic(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileCore})
	text := "keys: " + fakeAWSKeyID + " / " + fakeAWSSecret + " / " + fakeGitHubPAT +
		" / " + fakeOpenAIKey + " / " + fakeSlackBotToken

	first := s.Scan(context.Background(), []byte(text))
	for i := 0; i < 8; i++ {
		got := s.Scan(context.Background(), []byte(text))
		if len(got.Findings) != len(first.Findings) {
			t.Fatalf("run %d: %d findings, want %d", i, len(got.Findings), len(first.Findings))
		}
		for j := range got.Findings {
			a, b := first.Findings[j], got.Findings[j]
			if a.DetectorType != b.DetectorType || a.SecretSHA256 != b.SecretSHA256 {
				t.Fatalf("run %d finding %d: %s/%s != %s/%s", i, j,
					b.DetectorType, b.SecretSHA256, a.DetectorType, a.SecretSHA256)
			}
			if len(a.Spans) != len(b.Spans) || (len(a.Spans) > 0 && a.Spans[0] != b.Spans[0]) {
				t.Fatalf("run %d finding %d: spans %v != %v", i, j, b.Spans, a.Spans)
			}
		}
	}
}

func TestScanRespectsCancelledContext(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileCore})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Must return promptly rather than hang; empty findings are acceptable.
	report := s.Scan(ctx, []byte("token "+fakeGitHubPAT))
	_ = report
}

func TestParseConfigRejectsUnknownFields(t *testing.T) {
	if _, err := ParseConfig([]byte(`{"prfoile":"core"}`)); err == nil {
		t.Fatal("expected error for unknown field (typo should not be silently ignored)")
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Profile != DefaultProfile {
		t.Errorf("Profile = %q, want %q", cfg.Profile, DefaultProfile)
	}
	if cfg.MaxBytes != DefaultMaxBytes {
		t.Errorf("MaxBytes = %d, want %d", cfg.MaxBytes, DefaultMaxBytes)
	}
	if cfg.Verify {
		t.Error("Verify must default to false")
	}
	if !cfg.dropWordlistFPs() {
		t.Error("DropWordlistFPs must default to true")
	}
}

func TestVerifyDefaultsOffEvenWhenParsed(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"profile":"minimal"}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Verify {
		t.Fatal("verification must never be enabled implicitly")
	}
}

// One Scanner is shared across requests, so concurrent use must be safe. Run
// with -race to make this meaningful.
func TestConcurrentScansAreSafe(t *testing.T) {
	s := newTestScanner(t, Config{Profile: ProfileCore})

	inputs := []string{
		"token " + fakeGitHubPAT,
		"What is the capital of France?",
		"openai " + fakeOpenAIKey,
		"id=" + fakeAWSKeyID + " secret=" + fakeAWSSecret,
		"slack " + fakeSlackBotToken,
		strings.Repeat("harmless filler. ", 50),
	}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			text := inputs[i%len(inputs)]
			report := s.Scan(context.Background(), []byte(text))

			// Each input always or never yields findings; a concurrency bug shows
			// up as intermittently empty results.
			wantFindings := !strings.Contains(text, "capital of France") &&
				!strings.Contains(text, "harmless filler")
			if wantFindings && len(report.Findings) == 0 {
				errs <- "expected findings for " + text[:min(20, len(text))]
			}
			if !wantFindings && len(report.Findings) != 0 {
				errs <- "unexpected findings for clean input"
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
	}
}

func BenchmarkScanCleanText(b *testing.B) {
	s, err := New(Config{Profile: ProfileCore})
	if err != nil {
		b.Fatal(err)
	}
	data := []byte(strings.Repeat("Please summarise the following meeting notes. ", 40))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(context.Background(), data)
	}
}

func BenchmarkScanWithSecret(b *testing.B) {
	s, err := New(Config{Profile: ProfileCore})
	if err != nil {
		b.Fatal(err)
	}
	data := []byte(strings.Repeat("filler text ", 100) + fakeGitHubPAT)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Scan(context.Background(), data)
	}
}
