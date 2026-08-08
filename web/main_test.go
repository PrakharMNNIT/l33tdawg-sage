package web

import (
	"os"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/tx"
)

// TestMain shrinks the nonce-fence reconciliation schedule for this package.
//
// WHY THIS EXISTS: many tests here raise a REAL fence, and each paid the
// production 2s first-retry interval while draining it at teardown. The
// SAGE_TX_FENCE_*_MS environment knobs cannot fix that — internal/tx reads them
// once in its own init(), which runs before any TestMain in a foreign package
// can set them. That per-test cost pushed `go test -race ./web` past Go's
// DEFAULT 10-minute package timeout, so the command we document to reviewers
// failed with a timeout panic even when every test was correct. A branch that
// is green only if you know to pass a custom -timeout is not green.
//
// TIMEOUT HONESTY: even WITH these shrunken timings, the full -race suite runs
// ~540s on a fast dev machine (badger open/close dominates: 600+ tests
// averaging ~0.85s each), leaving under a minute of headroom before the 600s
// default fires on any machine ~10% slower. Until the per-test fixture cost is
// shaved, run this package as `go test -race -timeout 900s ./web`; a
// mid-suite "panic: test timed out" with zero failing tests is this headroom
// running out, not a red suite.
//
// The values are small but NOT zero: a zero retry interval would spin the
// reconciler hot and change the behaviour under test rather than just its
// speed. These keep the schedule real and merely brief.
func TestMain(m *testing.M) {
	restore := tx.SetFenceTimingsForTest(
		2*time.Second,        // attempt: still bounds one reconciliation attempt
		5*time.Millisecond,   // retry: the interval that dominated teardown
		50*time.Millisecond,  // retryMax: backoff ceiling
		100*time.Millisecond, // report: how often a held fence re-reports
	)
	code := m.Run()
	restore()
	os.Exit(code)
}
