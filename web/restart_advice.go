package web

import (
	"github.com/l33tdawg/sage/internal/tx"
)

// This file is the ONE place operator-facing "restart SAGE to finish" text is
// allowed to be composed. Several handlers persist a change and then need a
// process restart they cannot take themselves — the platform has no in-process
// re-exec, no restart hook is wired, or the automatic restart failed — and each
// used to hand the operator its own "fully quit SAGE and open it again" string.
// That instruction is dangerous while a signing key is fenced: the fence is
// in-process only, so a manual quit-and-reopen discards the only record that a
// transaction may still be in flight, the allocator re-seeds below it, and a
// later nonce overtakes it into an untraceable Code 4 loss. cmd/sage-gui VETOES
// the coordinated restart path for exactly this reason (tx.RestartVetoReason);
// a handler advising the manual path was telling the operator to do by hand
// precisely what the veto refuses — in the worst case (the embeddings switch)
// AFTER the veto had already fired and been swallowed.

// manualRestartAdvice returns instruction verbatim when no signing key is
// fenced, and a do-not-restart hold notice when one is. Every handler message
// that tells an operator to quit, relaunch, reopen or restart SAGE by hand MUST
// be routed through it; composing such an instruction anywhere else is how the
// bypass this file closes gets reintroduced.
//
// HONESTY ABOUT WHAT THIS IS: advice, not enforcement. It names the fence state
// at the instant the message was composed, and a fence can rise or clear
// between this string reaching the operator and the operator acting on it — a
// string cannot be atomic with a restart that happens later. The ENFORCED
// check lives on the restart paths themselves: handleRestart re-reads the veto
// on every request, and the coordinated path in cmd/sage-gui re-checks it
// under quiesce after the in-flight population has drained (see
// signer_fence_restart.go there). The manual quit-and-reopen lane has no
// enforcement hook at all — the process cannot intercept Cmd-Q — which is
// exactly why the ADVICE must refuse to recommend it while a fence is held:
// for that lane the message is the only control that exists.
func manualRestartAdvice(instruction string) string {
	reason := tx.RestartVetoReason()
	if reason == "" {
		return instruction
	}
	return "Do not quit or restart SAGE yet: " + reason
}
