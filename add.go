// Package add is Attack-Driven Development as a Go test library: it makes
// proving an attack as natural as writing a unit test, and it rides `go test`
// — there is no separate runner, CLI, or config.
//
// A Technique pairs a real attack with the control that closes it, and add.Run
// asserts the ADD invariant that a plain unit test cannot: the attack must
// actually breach the undefended path (so the test proves something) AND the
// control must block it. A control that silently stops being wired flips the
// defended ASR above zero and reds the build.
//
// What it is for: an embedded team hardening its OWN Go AI/agentic product,
// white-box and in-process. What it is NOT for: black-box scanning, static
// analysis (SAST/SCA/secret-scanning — use dedicated tools), or vuln-report
// generation. The output is a reproducible pass/fail + an attack-success-rate,
// not a severity list.
//
// It builds on gorauder (seeds, converters, scorers, the run+score engine);
// add supplies the paired-target invariant, the unit-vs-wired distinction, and
// the OWASP coverage grid an embedded team tracks over time.
package add

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/t0ul/gorauder"
)

// DefaultBlockedSentinel is what a defended target returns to signal it refused
// an attack; the default scorer treats its presence as a FAILED attack. Pick
// your own per technique if this collides with real output.
const DefaultBlockedSentinel = "[[DEFENSE-BLOCKED]]"

// Technique is one attack-driven case.
//
// Preconditions (the cost of honesty, deliberately required):
//   - Seeds: the attack(s), as gorauder seeds (with a success Marker).
//   - Undefended: the control REMOVED — the counterfactual that proves the
//     attack is real. You must keep this path reachable in tests.
//   - Defended: the real control. The attack must fail against it.
//
// Optional:
//   - Wired: an INTEGRATION target that drives the real pipeline end to end.
//     White-box unit targets prove the control's logic; Wired proves the control
//     is actually ON the path (a control that exists but isn't called passes
//     unit and fails here).
//   - Scorer: the oracle. Defaults to BlockAwareScorer(MarkerScorer) so a block
//     counts as a failed attack and a surviving Marker counts as a breach.
//   - Converters: obfuscation/mutation (gorauder). Default: Identity only.
//   - BlockedSentinel: override the default sentinel for the default scorer.
type Technique struct {
	Name            string
	Risk            string // OWASP tag, e.g. "LLM01", "ASI07" — drives the coverage grid
	Seeds           []gorauder.Seed
	Undefended      gorauder.Target
	Defended        gorauder.Target
	Wired           gorauder.Target
	Scorer          gorauder.Scorer
	Converters      []gorauder.Converter
	BlockedSentinel string
}

// Outcome is the measured result of a technique.
type Outcome struct {
	Name          string
	Risk          string
	Attacks       int
	UndefendedASR float64
	DefendedASR   float64
	WiredASR      float64 // -1 when no Wired target was supplied
}

func (tech Technique) scorer() gorauder.Scorer {
	if tech.Scorer != nil {
		return tech.Scorer
	}
	sentinel := tech.BlockedSentinel
	if sentinel == "" {
		sentinel = DefaultBlockedSentinel
	}
	return gorauder.BlockAwareScorer{BlockedSentinel: sentinel, Inner: gorauder.MarkerScorer{}}
}

func (tech Technique) run(ctx context.Context, target gorauder.Target) gorauder.Report {
	opts := []gorauder.Option{gorauder.WithScorer(tech.scorer())}
	if len(tech.Converters) > 0 { // else gorauder's default (Identity) applies
		opts = append(opts, gorauder.WithConverters(tech.Converters...))
	}
	return gorauder.NewRunner(target, opts...).Run(ctx, tech.Seeds)
}

// Evaluate runs the technique and returns its Outcome plus any invariant
// violations (empty = passed). It is pure (no *testing.T), so the library and
// its callers can test the pass/fail logic directly; Run wraps it for `go test`.
func Evaluate(tech Technique) (Outcome, []string) {
	out := Outcome{Name: tech.Name, Risk: tech.Risk, WiredASR: -1}
	var v []string
	if tech.Name == "" {
		v = append(v, "add: technique has no Name")
	}
	if len(tech.Seeds) == 0 {
		v = append(v, fmt.Sprintf("add: %q has no seeds", tech.Name))
	}
	if tech.Undefended == nil || tech.Defended == nil {
		v = append(v, fmt.Sprintf("add: %q needs both Undefended and Defended targets", tech.Name))
		return out, v
	}

	ctx := context.Background()
	und := tech.run(ctx, tech.Undefended)
	def := tech.run(ctx, tech.Defended)
	out.Attacks = und.Total
	out.UndefendedASR = und.ASR()
	out.DefendedASR = def.ASR()

	// Invariant 1 — the attack is real: without the control it must breach.
	if und.ASR() < 1.0 {
		v = append(v, fmt.Sprintf("%s [%s]: attack NOT PROVEN — undefended ASR %.0f%% (want 100%%); the test proves nothing",
			tech.Name, tech.Risk, und.ASR()*100))
	}
	// Invariant 2 — the control holds: with it, the attack must fail.
	if def.ASR() != 0.0 {
		v = append(v, fmt.Sprintf("%s [%s]: control FAILED — defended ASR %.0f%% (want 0%%)",
			tech.Name, tech.Risk, def.ASR()*100))
	}
	// Invariant 3 (optional) — the control is actually wired into the real path.
	if tech.Wired != nil {
		w := tech.run(ctx, tech.Wired)
		out.WiredASR = w.ASR()
		if w.ASR() != 0.0 {
			v = append(v, fmt.Sprintf("%s [%s]: control NOT WIRED — integration ASR %.0f%% (control exists but the real path isn't protected)",
				tech.Name, tech.Risk, w.ASR()*100))
		}
	}
	return out, v
}

// Run exercises one technique under `go test` and asserts the ADD invariant.
func Run(t testing.TB, tech Technique) Outcome {
	t.Helper()
	out, violations := Evaluate(tech)
	for _, msg := range violations {
		t.Error(msg)
	}
	return out
}

// Gate runs a whole suite as subtests, then logs the OWASP coverage grid. Each
// technique is an ordinary subtest (filter with `go test -run`); the grid is the
// artifact an embedded team tracks — it surfaces which risks are proven-and-
// defended and, via Coverage, which are not.
func Gate(t *testing.T, techniques ...Technique) []Outcome {
	t.Helper()
	outs := make([]Outcome, 0, len(techniques))
	for _, tech := range techniques {
		tech := tech
		t.Run(tech.Name, func(t *testing.T) {
			outs = append(outs, Run(t, tech))
		})
	}
	for _, line := range Grid(outs) {
		t.Log(line)
	}
	return outs
}

// Coverage maps each OWASP risk tag to the techniques proving it.
func Coverage(outs []Outcome) map[string][]string {
	m := map[string][]string{}
	for _, o := range outs {
		risk := o.Risk
		if risk == "" {
			risk = "(untagged)"
		}
		m[risk] = append(m[risk], o.Name)
	}
	return m
}

// Grid renders a human-readable coverage summary (one line per risk).
func Grid(outs []Outcome) []string {
	cov := Coverage(outs)
	risks := make([]string, 0, len(cov))
	for r := range cov {
		risks = append(risks, r)
	}
	sort.Strings(risks)
	lines := []string{fmt.Sprintf("ADD coverage: %d techniques across %d risk(s)", len(outs), len(cov))}
	for _, r := range risks {
		names := cov[r]
		sort.Strings(names)
		lines = append(lines, fmt.Sprintf("  %-8s %d: %v", r, len(names), names))
	}
	return lines
}
