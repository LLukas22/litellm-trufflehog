package scanner

import (
	"context"
	"strings"
	"testing"
)

// Synthetic credentials built to satisfy each detector's structural regex.
// None are real.
//
// They must also survive trufflehog's false-positive filters, which reject any
// unverified secret containing a term from DefaultFalsePositives ("example",
// "sample", "abcde", ...) or an English word from its embedded wordlist. That
// rules out the obvious placeholder shapes: AWS's published "EXAMPLE" keys and
// anything containing an alphabet run like "abcdefgh" are both discarded.
const (
	// idPat: (?:AKIA|ABIA|ACCA)[A-Z0-9]{16}
	fakeAWSKeyID = "AKIAQRSTUV234567WXYZ"
	// aws.SecretPat: [A-Za-z0-9+/]{40}, and must not match
	// FalsePositiveSecretPat ([a-f0-9]{40}) or it is dropped when unverified.
	fakeAWSSecret = "Xk8Qm2vN7pL5rT9wYb3dF6hJ1sA4gK0zC8nMxQ2e"

	// keyPat: sk-(?:...|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+
	fakeOpenAIKey = "sk-Qm7Xk2Vp9Rt4T3BlbkFJLs6Wn3Zy8Hq5Jd7Fg2Kv4Mb"

	// keyPat: (?:ghp|gho|...)_[a-zA-Z0-9_]{36,255}
	fakeGitHubPAT = "ghp_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5"

	// xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*
	fakeSlackBotToken = "xoxb-1234567890123-1234567890123-Qm7Xk2Vp9Rt4Ls6Wn3Zy8Hq5"
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

			// Collect every span reported for the expected detector and check
			// that each fragment we expect to be maskable is covered.
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

// The prefilter must not fire on ordinary prose, and must not fire on text that
// merely mentions providers without containing credentials.
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
	// Non-ASCII prefix: offsets are byte offsets, not rune offsets. If this
	// were confused anywhere the extracted slice would be garbage.
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

// Two occurrences of the same secret must produce two distinct spans, otherwise
// redaction would leave the second copy in place.
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

// trufflehog discards unverified results whose secret contains a placeholder
// term or an English dictionary word. This is upstream engine behaviour and it
// is usually what you want, but it can also discard a genuine credential that
// happens to contain a word, so it must remain switchable.
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
	// Vercel is in core but not minimal; adding it to minimal must widen the
	// detector set.
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

// A secret past MaxBytes is not scanned. This is a real limitation and the
// Truncated flag is how callers learn to treat the verdict as incomplete.
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

// Findings must not depend on map iteration order, or offsets would shuffle
// between identical requests.
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

	// Must return promptly rather than hang; findings may be empty and errors
	// populated, both acceptable.
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
