// Command add scaffolds Attack-Driven Design into a Go project.
//
//	add init [dir]
//
// init writes a security gate into an existing module: a techniques package with
// one working example, a `go test` gate, a one-command scorecard, a live-model
// test that fails (never skips) without models, a Makefile whose `check` target
// runs all of it, and a pre-push hook so a regression cannot leave the machine.
// It never overwrites an existing file. Run it in your module root (the dir with
// go.mod), then `go get` the three libraries it uses and `make hooks`.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "init" {
		fmt.Fprintln(os.Stderr, "usage: add init [dir]")
		os.Exit(2)
	}
	dir := "."
	if len(os.Args) >= 3 {
		dir = os.Args[2]
	}
	if err := run(dir); err != nil {
		fmt.Fprintln(os.Stderr, "add:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	mod, err := modulePath(filepath.Join(dir, "go.mod"))
	if err != nil {
		return fmt.Errorf("%w (run `go mod init <path>` first)", err)
	}
	files := map[string]string{
		"security/techniques.go": techniquesGo,
		"security/security_test.go": gateTestGo,
		"security/live_test.go":  liveTestGo,
		"cmd/scorecard/main.go":  strings.ReplaceAll(scorecardGo, "{{MODULE}}", mod),
		"Makefile":               makefile,
		".githooks/pre-push":     prePush,
	}
	for rel, content := range files {
		if err := writeNew(filepath.Join(dir, rel), content); err != nil {
			return err
		}
	}
	fmt.Print(nextSteps)
	return nil
}

// writeNew writes content unless the file already exists (never clobber).
func writeNew(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  skip   %s (exists)\n", path)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if strings.HasSuffix(path, "pre-push") {
		mode = 0o755
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return err
	}
	fmt.Printf("  create %s\n", path)
	return nil
}

func modulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", fmt.Errorf("no go.mod at %s", gomod)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("no module line in %s", gomod)
}

const techniquesGo = `// Package security holds this project's Attack-Driven Design techniques: each
// pairs a real attack with the control that closes it. ` + "`make check`" + ` runs them.
//
// Replace the example with your app's real controls. The rule the gate enforces:
// Undefended is the control REMOVED (the attack must land, or the test proves
// nothing), and Defended is the real control (the attack must fail).
package security

import (
	"context"

	add "github.com/t0ul/ADD"
	"github.com/t0ul/gorauder"
)

// Techniques returns the project's ADD techniques.
func Techniques() []add.Technique {
	return []add.Technique{
		exampleInjection(),
	}
}

// exampleInjection is a starter that passes out of the box so the gate is green
// on day one. It takes the attack from gorauder's built-in injection catalog, an
// undefended target that reflects input (so the injection lands), and a defended
// target that refuses. Swap both targets for your app's real ones.
func exampleInjection() add.Technique {
	return add.Technique{
		Name:  "example-injection",
		Risk:  gorauder.LLM01PromptInjection,
		Seeds: gorauder.CatalogSeeds(gorauder.LLM01PromptInjection),
		Undefended: gorauder.TargetFunc(func(_ context.Context, prompt string) (string, error) {
			return prompt, nil // reflects the attack verbatim: the marker survives
		}),
		Defended: gorauder.TargetFunc(func(_ context.Context, _ string) (string, error) {
			return add.DefaultBlockedSentinel, nil // a real control refuses the attack
		}),
	}
}
`

const gateTestGo = `package security

import (
	"testing"

	add "github.com/t0ul/ADD"
)

// TestGate runs every technique as a subtest and logs the OWASP coverage grid.
// It is the ` + "`go test`" + ` half of ` + "`make check`" + `.
func TestGate(t *testing.T) {
	add.Gate(t, Techniques()...)
}
`

const liveTestGo = `//go:build live

package security

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/t0ul/goserve"
)

// TestLiveModelReachable boots the project's local model through goserve and
// asserts it answers. It FAILS (never skips) when the lab is missing, because a
// gate that skips is not a gate. Point your live technique targets at
// h.ChatURL(...) to attack the real model path here.
//
// Configure with env: GOSERVE_DIR (GGUF dir), GOSERVE_MODEL (file),
// GOSERVE_PORT is fixed below for simplicity.
func TestLiveModelReachable(t *testing.T) {
	dir := os.Getenv("GOSERVE_DIR")
	if dir == "" {
		dir = "set-up/vm-assets"
	}
	model := os.Getenv("GOSERVE_MODEL")
	if model == "" {
		model = "llama-3.2-3b.gguf"
	}
	cfg := goserve.Config{
		Dir:          dir,
		Reclaim:      true,
		ReadyTimeout: 120 * time.Second,
		Stdout:       io.Discard,
		Models:       []goserve.Model{{Name: "planner", File: model, Port: 11435, Ctx: 8192}},
	}
	if ok, msg := cfg.Available(); !ok {
		t.Fatalf("live lab not set up (%s); do not skip the live gate", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	h, err := goserve.Start(ctx, cfg)
	if err != nil {
		t.Fatalf("goserve.Start: %v", err)
	}
	defer h.Close()

	body := []byte(` + "`" + `{"model":"planner","messages":[{"role":"user","content":"Reply READY."}],"max_tokens":8,"temperature":0}` + "`" + `)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.ChatURL("planner"), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("chat request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("chat status %d: %s", resp.StatusCode, out)
	}
}
`

const scorecardGo = `// Command scorecard runs the project's ADD techniques and prints the attack
// success rate before and after each control, plus the OWASP coverage grid. It
// exits non-zero if any invariant is violated, so it doubles as a gate.
package main

import (
	"fmt"
	"os"

	add "github.com/t0ul/ADD"
	"{{MODULE}}/security"
)

func main() {
	fmt.Println("== security scorecard (ADD: ASR before -> after) ==")
	fmt.Printf("%-24s %-8s %8s %8s\n", "technique", "risk", "before", "after")
	var outs []add.Outcome
	failed := 0
	for _, tech := range security.Techniques() {
		out, violations := add.Evaluate(tech)
		outs = append(outs, out)
		flag := "ok"
		if len(violations) > 0 {
			flag = "FAIL"
			failed++
		}
		fmt.Printf("%-24s %-8s %7.0f%% %7.0f%%  %s\n", out.Name, out.Risk, out.UndefendedASR*100, out.DefendedASR*100, flag)
		for _, v := range violations {
			fmt.Printf("    ! %s\n", v)
		}
	}
	fmt.Println()
	for risk, names := range add.Coverage(outs) {
		fmt.Printf("  %-8s %d: %v\n", risk, len(names), names)
	}
	if failed > 0 {
		fmt.Printf("\n%d technique(s) failed\n", failed)
		os.Exit(1)
	}
	fmt.Printf("\nall defenses hold: ASR 0%% across %d technique(s).\n", len(outs))
}
`

const makefile = `# Security gate. It tests reality: the ADD scorecard, the unit tests, and the
# live suite against a local model. Install the hook once with ` + "`make hooks`" + `;
# after that nothing is pushed while a defense is red.
#
#   make check      scorecard + tests + live (the gate; what the hook runs)
#   make scorecard  ASR before/after per control + the OWASP grid
#   make test       unit tests (the ADD gate)
#   make live       the same attacks reach the real local model
#   make hooks      install .githooks/pre-push

SHELL := /bin/bash

.PHONY: check scorecard test live hooks

check: scorecard test live

scorecard:
	go run ./cmd/scorecard

test:
	go test -count=1 ./...

live:
	go test -count=1 -tags live ./...

hooks:
	@git config core.hooksPath .githooks && echo "pre-push hook installed: make check runs before every push"
`

const prePush = `#!/usr/bin/env bash
# Local gate: every attack re-runs, live model included, before anything leaves
# this machine. Install once with ` + "`make hooks`" + `.
set -e
cd "$(git rev-parse --show-toplevel)"
make check
`

const nextSteps = `
Next:
  go get github.com/t0ul/ADD github.com/t0ul/gorauder github.com/t0ul/goserve
  make hooks
  make check
Then replace the example technique in security/techniques.go with your real controls.
`
