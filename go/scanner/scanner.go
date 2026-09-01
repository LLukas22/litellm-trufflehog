// Package scanner wraps trufflehog's detection engine for low-latency,
// in-memory scanning of text.
//
// It deliberately does not use trufflehog's engine.Engine, which is built
// around source enumeration: it requires a SourceManager and starts four pools
// of worker goroutines plus buffered channels sized off NumCPU. For scanning a
// single prompt on the request path we only need the detection core the engine
// wraps - an Aho-Corasick keyword prefilter over the detector set, then
// Detector.FromData on the windows that matched. That is what this package
// does, synchronously, with no background goroutines outliving a call.
package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	re2 "github.com/wasilibs/go-re2"

	thconfig "github.com/trufflesecurity/trufflehog/v3/pkg/config"
	thcontext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Scanner holds a resolved detector set and its Aho-Corasick prefilter.
//
// Construction is expensive (the trie is built over every keyword of every
// selected detector), so a Scanner is meant to be created once and reused. It
// is safe for concurrent use: Detector.FromData is documented as callable from
// multiple goroutines, and Scan keeps all mutable state on the stack.
type Scanner struct {
	cfg          Config
	core         *ahocorasick.Core
	detectors    []detectors.Detector
	thctx        thcontext.Context
	warmupErrors []string
}

// New resolves the configured detector set and builds the prefilter.
func New(cfg Config) (*Scanner, error) {
	cfg = cfg.withDefaults()

	dets, err := resolveDetectors(cfg)
	if err != nil {
		return nil, err
	}

	var opts []ahocorasick.CoreOption
	if cfg.ScanEntireChunk {
		opts = append(opts, ahocorasick.WithSpanCalculator(new(ahocorasick.EntireChunkSpanCalculator)))
	}

	s := &Scanner{
		cfg:       cfg,
		core:      ahocorasick.NewAhoCorasickCore(dets, opts...),
		detectors: dets,
		thctx:     thcontext.Background(),
	}
	if !cfg.SkipWarmup {
		s.warmupErrors = s.warm()
	}
	return s, nil
}

// warm performs the lazy, process-wide initialisation that would otherwise
// happen inside the first real request.
//
// The expensive and failure-prone part is github.com/wasilibs/go-re2, which
// many detectors use for their patterns: it runs RE2 inside a wazero WASM
// runtime that is compiled and instantiated on first regex execution, not at
// package init. Forcing one match here moves that cost to construction and
// surfaces any failure through WarmupErrors instead of silently dropping a
// detector mid-request.
//
// Note that calling FromData with a payload that matches nothing is not enough:
// detectors return before executing their patterns, so the RE2 runtime is never
// touched. Hence the explicit regex below.
func (s *Scanner) warm() []string {
	var errs []string

	func() {
		defer func() {
			if r := recover(); r != nil {
				errs = append(errs, fmt.Sprintf("re2 runtime init: %v", r))
			}
		}()
		re := re2.MustCompile(`warmup-[0-9a-f]{4}-litellm-trufflehog`)
		if !re.MatchString("warmup-1a2b-litellm-trufflehog") {
			errs = append(errs, "re2 runtime init: warmup pattern failed to match")
		}
	}()

	// Then give each detector one benign call, so any per-detector lazy setup
	// also happens now.
	const payload = "litellm-trufflehog warmup"
	for _, d := range s.detectors {
		func() {
			defer func() {
				if r := recover(); r != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", detectorKey(d), r))
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.detectorTimeout())
			defer cancel()
			//nolint:errcheck // results and errors are irrelevant; we want the side effect
			_, _ = d.FromData(ctx, false, []byte(payload))
		}()
	}
	return errs
}

// WarmupErrors reports detectors that failed their one-time initialisation.
// A non-empty result means those detectors may be unreliable.
//
// The slice is always non-nil so that it marshals to a JSON array rather than
// null.
func (s *Scanner) WarmupErrors() []string {
	out := make([]string, 0, len(s.warmupErrors))
	return append(out, s.warmupErrors...)
}

// Config returns the effective configuration, with defaults applied.
func (s *Scanner) Config() Config { return s.cfg }

// DetectorCount returns the number of active detectors.
func (s *Scanner) DetectorCount() int { return len(s.detectors) }

// task is one detector invocation: a detector paired with one window of input
// that its keywords matched.
type task struct {
	match *ahocorasick.DetectorMatch
	key   string
	chunk []byte
}

// Scan detects secrets in data. It never returns an error: detector-level
// failures are collected into Report.Errors so that one misbehaving detector
// cannot fail the whole request.
func (s *Scanner) Scan(ctx context.Context, data []byte) Report {
	started := time.Now()
	report := Report{Findings: []Finding{}}

	if len(data) > s.cfg.MaxBytes {
		data = data[:s.cfg.MaxBytes]
		report.Truncated = true
	}
	report.ScannedBytes = len(data)
	if len(data) == 0 {
		report.DurationMS = millis(time.Since(started))
		return report
	}

	// Aho-Corasick prefilter. For the overwhelmingly common case of text with
	// no credential-like keywords this returns nothing and we are done, which
	// is what keeps typical latency negligible.
	matches := s.core.FindDetectorMatches(data)
	if len(matches) == 0 {
		report.DurationMS = millis(time.Since(started))
		return report
	}

	// FindDetectorMatches builds its result from a map, so its order varies
	// between runs. Sort by detector ID to make findings (and the offsets
	// derived from them) deterministic.
	sort.Slice(matches, func(i, j int) bool {
		return detectorKey(matches[i].Detector) < detectorKey(matches[j].Detector)
	})

	tasks := make([]task, 0, len(matches))
	for _, m := range matches {
		key := detectorKey(m.Detector)
		for _, chunk := range m.Matches() {
			tasks = append(tasks, task{match: m, key: key, chunk: chunk})
		}
	}

	results := make([][]detectors.Result, len(tasks))
	taskErrs := make([]error, len(tasks))
	s.runTasks(ctx, tasks, results, taskErrs)

	tracker := newOffsetTracker(data)
	seen := make(map[string]struct{})

	for i, t := range tasks {
		if err := taskErrs[i]; err != nil {
			report.Errors = append(report.Errors,
				fmt.Sprintf("%s: %v", t.key, err))
		}
		isFP := detectors.GetFalsePositiveCheck(t.match.Detector)
		for _, res := range results[i] {
			f, ok := s.buildFinding(t, res, tracker, isFP, seen)
			if !ok {
				continue
			}
			report.Findings = append(report.Findings, f)
		}
	}

	report.DurationMS = millis(time.Since(started))
	return report
}

// runTasks invokes every detector task, bounded by Config.Concurrency.
func (s *Scanner) runTasks(ctx context.Context, tasks []task, results [][]detectors.Result, errs []error) {
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup

	for i := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// A panicking third-party detector must not take down the proxy.
			defer func() {
				if r := recover(); r != nil {
					errs[i] = fmt.Errorf("detector panicked: %v", r)
				}
			}()

			res, err := s.runDetector(ctx, tasks[i])
			results[i], errs[i] = res, err
		}(i)
	}
	wg.Wait()
}

func (s *Scanner) runDetector(ctx context.Context, t task) ([]detectors.Result, error) {
	dctx, cancel := context.WithTimeout(ctx, s.cfg.detectorTimeout())
	defer cancel()

	// Detectors may return partial results alongside an error (e.g. a
	// verification request timed out), so keep whatever came back.
	res, err := t.match.Detector.FromData(dctx, s.cfg.Verify, t.chunk)
	return s.filterResults(t.match.Detector, res), err
}

// filterResults mirrors engine.filterResults so that behaviour matches the
// trufflehog CLI for the same flags.
func (s *Scanner) filterResults(d detectors.Detector, results []detectors.Result) []detectors.Result {
	if len(results) == 0 {
		return results
	}

	clean := detectors.CleanResults
	ignoreConfig := false
	if cleaner, ok := d.(detectors.CustomResultsCleaner); ok {
		clean = cleaner.CleanResults
		ignoreConfig = cleaner.ShouldCleanResultsIrrespectiveOfConfiguration()
	}
	if s.cfg.FilterUnverified || ignoreConfig {
		results = clean(results, s.cfg.Verify)
	}

	if s.cfg.FilterEntropy > 0 {
		results = detectors.FilterResultsWithEntropy(s.thctx, results, s.cfg.FilterEntropy, false)
	}
	return results
}

// buildFinding converts a detector result into a Finding, deduplicating and
// applying the wordlist false-positive filter. It reports false when the result
// should be dropped.
func (s *Scanner) buildFinding(
	t task,
	res detectors.Result,
	tracker *offsetTracker,
	isFP func(detectors.Result) (bool, string),
	seen map[string]struct{},
) (Finding, bool) {
	// Prefer the composed multi-part value for identity, so that two parts of
	// the same credential are not counted as two secrets.
	identity := res.Raw
	if len(res.RawV2) > 0 {
		identity = res.RawV2
	}
	if len(identity) == 0 {
		return Finding{}, false
	}

	wordlistFP := false
	if !res.Verified && res.Raw != nil && isFP != nil {
		wordlistFP, _ = isFP(res)
		if wordlistFP && s.cfg.dropWordlistFPs() {
			return Finding{}, false
		}
	}

	spans := tracker.spansFor(t.key, candidateSecrets(res.GetPrimarySecretValue(), res.Raw, res.RawV2))

	sum := sha256Hex(identity)
	dedupe := t.key + "\x00" + sum
	if len(spans) > 0 {
		dedupe = fmt.Sprintf("%s\x00%d", dedupe, spans[0].Start)
	}
	if _, dup := seen[dedupe]; dup {
		return Finding{}, false
	}
	seen[dedupe] = struct{}{}

	f := Finding{
		DetectorType:          res.DetectorType.String(),
		DetectorName:          res.DetectorName,
		Description:           t.match.Detector.Description(),
		Verified:              res.Verified,
		Redacted:              res.Redacted,
		SecretSHA256:          sum,
		Spans:                 spans,
		ExtraData:             res.ExtraData,
		WordlistFalsePositive: wordlistFP,
	}
	if err := res.VerificationError(); err != nil {
		f.VerificationError = err.Error()
	}
	if s.cfg.IncludeRaw {
		f.Raw = string(identity)
	}
	return f, true
}

// detectorKey is a stable identifier for a detector, including version, e.g.
// "Github.v2".
func detectorKey(d detectors.Detector) string {
	return thconfig.GetDetectorID(d).String()
}

func millis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
