package scanner

import (
	"strings"
	"testing"

	thconfig "github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// TestProfileNamesAreValidDetectors is the guard that keeps the curated
// profiles honest. Every name must (a) parse as a trufflehog detector selector
// and (b) match at least one detector that trufflehog actually ships. Without
// this, a renamed or removed upstream detector would silently reduce coverage
// on the next dependency bump instead of failing the build.
func TestProfileNamesAreValidDetectors(t *testing.T) {
	all := defaults.DefaultDetectors()

	for _, profile := range []string{ProfileMinimal, ProfileCore} {
		names, err := profileNames(profile)
		if err != nil {
			t.Fatalf("profileNames(%q): %v", profile, err)
		}

		for _, name := range names {
			id, err := thconfig.ParseDetector(name)
			if err != nil {
				t.Errorf("profile %q: %q does not parse as a detector: %v", profile, name, err)
				continue
			}

			set := map[thconfig.DetectorID]struct{}{id: {}}
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
	for _, profile := range []string{ProfileMinimal, ProfileCore} {
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

// The whole point of a curated default is that it is much smaller than "all"
// while minimal is smaller still.
func TestProfileSizesAreOrdered(t *testing.T) {
	count := func(profile string) int {
		s, err := New(Config{Profile: profile})
		if err != nil {
			t.Fatalf("New(%q): %v", profile, err)
		}
		return s.DetectorCount()
	}

	minimal, core, all := count(ProfileMinimal), count(ProfileCore), count(ProfileAll)
	t.Logf("detector counts: minimal=%d core=%d all=%d", minimal, core, all)

	if !(minimal < core && core < all) {
		t.Errorf("expected minimal < core < all, got %d < %d < %d", minimal, core, all)
	}
	if core >= all/2 {
		t.Errorf("core profile (%d) should be far smaller than all (%d)", core, all)
	}
}

// "Generic" is trufflehog's catch-all detector and the dominant source of false
// positives. It must never be enabled implicitly.
func TestGenericDetectorNotInDefaultProfiles(t *testing.T) {
	for _, profile := range []string{ProfileMinimal, ProfileCore} {
		names, err := profileNames(profile)
		if err != nil {
			t.Fatalf("profileNames(%q): %v", profile, err)
		}
		for _, n := range names {
			if strings.EqualFold(n, "Generic") {
				t.Errorf("profile %q must not include the Generic detector", profile)
			}
		}
	}
}

func TestUnknownProfileRejected(t *testing.T) {
	if _, err := New(Config{Profile: "everything"}); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}
