package scanner

import (
	"context"
	"strings"
	"testing"

	thconfig "github.com/trufflesecurity/trufflehog/v3/pkg/config"
)

// Every curated name must parse as a detector selector and match a detector
// trufflehog actually ships, so an upstream rename or removal fails the build
// instead of silently reducing coverage.
func TestProfileNamesAreValidDetectors(t *testing.T) {
	all := allDetectors()

	for _, profile := range []string{ProfileMinimal, ProfileCore, ProfileParanoid} {
		names, err := profileNames(profile)
		if err != nil {
			t.Fatalf("profileNames(%q): %v", profile, err)
		}

		for _, name := range names {
			if strings.EqualFold(name, ProfileAll) {
				// A special group rather than a detector name; its expansion is
				// covered by TestProfileSizesAreOrdered.
				continue
			}

			// parseDetectorIDs, not thconfig.ParseDetector: it also resolves our
			// own selector aliases.
			set, err := parseDetectorIDs([]string{name})
			if err != nil {
				t.Errorf("profile %q: %q does not parse as a detector: %v", profile, name, err)
				continue
			}

			found := false
			for _, d := range all {
				if inSet(d, set) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("profile %q: %q parses but no shipped detector implements it "+
					"(likely 'not yet implemented' upstream - remove it)", profile, name)
			}
		}
	}
}

func TestProfileNamesHaveNoDuplicates(t *testing.T) {
	for _, profile := range []string{ProfileMinimal, ProfileCore, ProfileParanoid} {
		names, err := profileNames(profile)
		if err != nil {
			t.Fatalf("profileNames(%q): %v", profile, err)
		}
		seen := make(map[string]struct{}, len(names))
		for _, n := range names {
			k := strings.ToLower(n)
			if _, dup := seen[k]; dup {
				t.Errorf("profile %q: duplicate detector %q", profile, n)
			}
			seen[k] = struct{}{}
		}
	}
}

// The curated default must stay much smaller than "all", and minimal smaller
// still. "paranoid" is "all" plus the catch-all, so it is the largest set.
func TestProfileSizesAreOrdered(t *testing.T) {
	count := func(profile string) int {
		s, err := New(Config{Profile: profile})
		if err != nil {
			t.Fatalf("New(%q): %v", profile, err)
		}
		return s.DetectorCount()
	}

	minimal, core := count(ProfileMinimal), count(ProfileCore)
	all, paranoid := count(ProfileAll), count(ProfileParanoid)
	t.Logf("detector counts: minimal=%d core=%d all=%d paranoid=%d",
		minimal, core, all, paranoid)

	if !(minimal < core && core < all && all < paranoid) {
		t.Errorf("expected minimal < core < all < paranoid, got %d < %d < %d < %d",
			minimal, core, all, paranoid)
	}
	if core >= all/2 {
		t.Errorf("core profile (%d) should be far smaller than all (%d)", core, all)
	}
	// Generic is the only thing "paranoid" adds.
	if paranoid != all+1 {
		t.Errorf("paranoid (%d) should be all (%d) plus Generic alone", paranoid, all)
	}
}

// The catch-all detectors are the dominant source of false positives, so no
// profile may enable one implicitly. "paranoid" enables ours and only ours;
// trufflehog's Generic stays opt-in by name so that profiles never change its
// behaviour or ours.
func TestCatchAllDetectorsAreNotImplicit(t *testing.T) {
	selects := func(profile, selector string) bool {
		names, err := profileNames(profile)
		if err != nil {
			t.Fatalf("profileNames(%q): %v", profile, err)
		}
		for _, n := range names {
			if strings.EqualFold(n, selector) {
				return true
			}
		}
		return false
	}

	for _, profile := range []string{ProfileMinimal, ProfileCore, ProfileAll} {
		for _, selector := range []string{"Generic", catchAllSelector} {
			if selects(profile, selector) {
				t.Errorf("profile %q must not include the %s detector", profile, selector)
			}
		}
	}
	if !selects(ProfileParanoid, catchAllSelector) {
		t.Errorf("profile %q must include the %s detector", ProfileParanoid, catchAllSelector)
	}
	if selects(ProfileParanoid, "Generic") {
		t.Errorf("profile %q must not include trufflehog's Generic detector", ProfileParanoid)
	}
}

// Neither catch-all is in defaults.DefaultDetectors - upstream ships Generic
// commented out, and ours is not upstream's - so without extraDetectors no
// selector could resolve to either.
func TestCatchAllDetectorsAreSelectableByName(t *testing.T) {
	base, err := New(Config{Profile: ProfileCore})
	if err != nil {
		t.Fatalf("New(core): %v", err)
	}

	for _, tc := range []struct {
		selectors []string
		extra     int
	}{
		{[]string{"Generic"}, 1},
		{[]string{catchAllSelector}, 1},
		{[]string{"generic", "highentropy"}, 2}, // selectors are case-insensitive
	} {
		s, err := New(Config{Profile: ProfileCore, IncludeDetectors: tc.selectors})
		if err != nil {
			t.Fatalf("New(core+%v): %v", tc.selectors, err)
		}
		if got, want := s.DetectorCount(), base.DetectorCount()+tc.extra; got != want {
			t.Errorf("include_detectors=%v resolved to %d detectors, want %d",
				tc.selectors, got, want)
		}
	}
}

// The pool must not count a detector twice if an upstream release starts
// shipping one of our extras in its defaults.
func TestDetectorPoolHasNoDuplicates(t *testing.T) {
	seen := make(map[thconfig.DetectorID]struct{})
	for _, d := range allDetectors() {
		id := thconfig.GetDetectorID(d)
		if _, dup := seen[id]; dup {
			t.Errorf("duplicate detector in pool: %s", id)
		}
		seen[id] = struct{}{}
	}
}

// The point of the profile: credentials with no recognisable issuer, which every
// provider-specific detector is blind to.
func TestParanoidProfileFindsUnbrandedSecret(t *testing.T) {
	const payload = "SEARCH_API_KEY: " + fakeUnbrandedSecret

	// "all" must stay free of the catch-all: it expands to every DetectorID in
	// the protobuf, so it would otherwise pull Generic in by accident.
	for _, profile := range []string{ProfileCore, ProfileAll} {
		s, err := New(Config{Profile: profile})
		if err != nil {
			t.Fatalf("New(%q): %v", profile, err)
		}
		if got := s.Scan(context.Background(), []byte(payload)); len(got.Findings) != 0 {
			t.Errorf("profile %q: expected no findings, got %d", profile, len(got.Findings))
		}
	}

	paranoid, err := New(Config{Profile: ProfileParanoid})
	if err != nil {
		t.Fatalf("New(paranoid): %v", err)
	}
	report := paranoid.Scan(context.Background(), []byte(payload))
	if len(report.Findings) == 0 {
		t.Fatal("paranoid profile: expected a finding")
	}
	if got := report.Findings[0].DetectorName; got != catchAllSelector {
		t.Errorf("expected a %s finding, got %q", catchAllSelector, got)
	}
	if len(report.Findings[0].Spans) == 0 {
		t.Error("expected a locatable span, so the value can be redacted")
	}
}

// The catch-all must be removable again, like any other detector.
func TestParanoidProfileRespectsExcludes(t *testing.T) {
	s, err := New(Config{
		Profile:          ProfileParanoid,
		ExcludeDetectors: []string{catchAllSelector},
	})
	if err != nil {
		t.Fatalf("New(paranoid, -%s): %v", catchAllSelector, err)
	}
	all, err := New(Config{Profile: ProfileAll})
	if err != nil {
		t.Fatalf("New(all): %v", err)
	}
	if got, want := s.DetectorCount(), all.DetectorCount(); got != want {
		t.Errorf("paranoid minus %s resolved to %d detectors, want %d",
			catchAllSelector, got, want)
	}
}

// The reason our own catch-all exists. trufflehog's Generic discards any
// candidate that base64-decodes, so it cannot see a token that happens to be a
// multiple of four characters from the base64 alphabet; "paranoid" can.
func TestParanoidProfileFindsBase64ShapedSecret(t *testing.T) {
	const payload = "SCIM_TOKEN: " + fakeBase64ShapedSecret

	paranoid, err := New(Config{Profile: ProfileParanoid})
	if err != nil {
		t.Fatalf("New(paranoid): %v", err)
	}
	report := paranoid.Scan(context.Background(), []byte(payload))
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (%v)", len(report.Findings),
			detectorTypes(report))
	}
	if got := string(payload[report.Findings[0].Spans[0].Start:report.Findings[0].Spans[0].End]); got != fakeBase64ShapedSecret {
		t.Errorf("span covered %q, want the token", got)
	}

	// Pin the upstream limitation this works around, so that an upstream fix
	// shows up here rather than going unnoticed.
	generic, err := New(Config{Profile: ProfileCore, IncludeDetectors: []string{"Generic"}})
	if err != nil {
		t.Fatalf("New(core+Generic): %v", err)
	}
	if got := generic.Scan(context.Background(), []byte(payload)); len(got.Findings) != 0 {
		t.Errorf("trufflehog's Generic now reports base64-shaped values (%d findings); "+
			"our catch-all may no longer be needed", len(got.Findings))
	}
}

func TestUnknownProfileRejected(t *testing.T) {
	if _, err := New(Config{Profile: "everything"}); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}
