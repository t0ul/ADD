package add

import (
	"regexp"
	"testing"
)

// FuzzSanitizer is the discovery complement to a seed-based ADD case for a
// string sanitizer/filter: it seeds the fuzz corpus from the known attacks, then
// coverage-guided-mutates inputs looking for one where a forbidden pattern
// (badRe — e.g. a surviving URL or shell metacharacter) appears in the
// sanitizer's OUTPUT. A hit is a bypass the hand-written seeds missed; Go saves
// it to testdata/fuzz (it then replays in plain `go test`), and it should be
// promoted into an ADD seed so the discovery becomes permanent regression.
//
// Use it for controls whose success is a syntactic invariant on the output, not
// a planted marker (markers get mutated away). Call from a FuzzXxx(f *testing.F).
func FuzzSanitizer(f *testing.F, seeds []string, transform func(string) string, badRe *regexp.Regexp) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if out := transform(in); badRe.MatchString(out) {
			t.Fatalf("sanitizer bypass: %q -> %q (forbidden %s survived)", in, out, badRe)
		}
	})
}

// FuzzInvariant is the generic form: seed the corpus, then assert a property for
// every input. Use for robustness (the body just calls the parser — go fuzz
// catches a panic/hang) or any custom invariant (e.g. an extractor never emits a
// date absent from its input). The invariant body fails via t.Fatal.
func FuzzInvariant(f *testing.F, seeds []string, invariant func(t *testing.T, in string)) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(invariant)
}
