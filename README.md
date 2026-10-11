# ADD

Attack-Driven Design for building Go based AI projects.

A `Technique` pairs a real attack with the control that closes it, and the gate
asserts the invariant a plain unit test cannot: the attack must breach the
undefended path (so the test proves something) AND the control must block it. It
rides `go test`, no separate runner.

```go
add.Gate(t, Techniques()...) // each technique a subtest; logs the OWASP grid
out, violations := add.Evaluate(tech) // pure, for a one-command scorecard
```

It builds on [`gorauder`](https://github.com/t0ul/gorauder) (seeds, converters,
scorers, the run+score engine) and pairs with
[`goserve`](https://github.com/t0ul/goserve) to run the same suite against a real
local model.

## Scaffolding a project

Drop the whole gate into any Go module:

```bash
go run github.com/t0ul/ADD/cmd/add@latest init .
go get github.com/t0ul/ADD github.com/t0ul/gorauder github.com/t0ul/goserve
make hooks
make check
```

`add init` writes a `security` package with one working example technique, a
`go test` gate, a one-command scorecard, a live-model test that fails (never
skips) without models, a `Makefile` whose `check` runs scorecard + tests + live,
and a pre-push hook so a regression cannot leave the machine. `make check` is
green on day one; then replace the example with your app's real controls.
