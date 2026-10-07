package add_test

import (
	"context"
	"testing"

	"github.com/t0ul/ADD"
	"github.com/t0ul/gorauder"
)

func seed() []gorauder.Seed {
	return []gorauder.Seed{{ID: "t1", Technique: "demo", Prompt: "attack", Marker: "PWN", Objective: "prove it"}}
}

func breaches() gorauder.Target { // undefended: the marker survives
	return gorauder.TargetFunc(func(context.Context, string) (string, error) { return "result: PWN", nil })
}

func blocks() gorauder.Target { // defended: returns the block sentinel
	return gorauder.TargetFunc(func(context.Context, string) (string, error) { return add.DefaultBlockedSentinel, nil })
}

// A well-formed technique passes with no violations and the expected ASRs.
func TestEvaluatePassesValidTechnique(t *testing.T) {
	out, v := add.Evaluate(add.Technique{
		Name: "demo", Risk: "LLM01", Seeds: seed(),
		Undefended: breaches(), Defended: blocks(),
	})
	if len(v) != 0 {
		t.Fatalf("expected no violations, got %v", v)
	}
	if out.UndefendedASR != 1.0 || out.DefendedASR != 0.0 {
		t.Fatalf("ASR wrong: undefended=%.2f defended=%.2f", out.UndefendedASR, out.DefendedASR)
	}
}

// Invariant 1: an attack that doesn't breach the undefended path is flagged —
// this is what stops the suite rotting into green tautologies.
func TestEvaluateFlagsUnprovenAttack(t *testing.T) {
	_, v := add.Evaluate(add.Technique{
		Name: "weak", Risk: "LLM01", Seeds: seed(),
		Undefended: blocks(), // attack fails even undefended -> not real
		Defended:   blocks(),
	})
	if len(v) == 0 {
		t.Fatal("expected a violation: undefended ASR below 100%")
	}
}

// Invariant 2: a control that lets the attack through is flagged.
func TestEvaluateFlagsBrokenControl(t *testing.T) {
	_, v := add.Evaluate(add.Technique{
		Name: "leaky", Risk: "LLM01", Seeds: seed(),
		Undefended: breaches(),
		Defended:   breaches(), // control doesn't block -> marker survives
	})
	if len(v) == 0 {
		t.Fatal("expected a violation: defended ASR above 0%")
	}
}

// Invariant 3: a control present at unit level but not wired into the real path.
func TestEvaluateFlagsUnwiredControl(t *testing.T) {
	_, v := add.Evaluate(add.Technique{
		Name: "unwired", Risk: "ASI05", Seeds: seed(),
		Undefended: breaches(), Defended: blocks(),
		Wired: breaches(), // integration path still breached
	})
	if len(v) == 0 {
		t.Fatal("expected a violation: wired/integration ASR above 0%")
	}
}

func TestCoverageGroupsByRisk(t *testing.T) {
	outs := []add.Outcome{{Name: "a", Risk: "LLM01"}, {Name: "b", Risk: "LLM01"}, {Name: "c", Risk: "ASI07"}}
	cov := add.Coverage(outs)
	if len(cov["LLM01"]) != 2 || len(cov["ASI07"]) != 1 {
		t.Fatalf("coverage grouping wrong: %v", cov)
	}
}
