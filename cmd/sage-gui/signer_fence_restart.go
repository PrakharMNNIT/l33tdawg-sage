package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/l33tdawg/sage/internal/tx"
)

// This file is the node's side of the signer fence's restart guard.
//
// WHY A COORDINATED RESTART IS THE DANGEROUS ONE. The fence in internal/tx is
// IN-PROCESS ONLY: it remembers that some transaction carrying nonce N went out
// and was never accounted for, and it refuses to let that key allocate anything
// higher until N's fate is proven. Nothing about that record survives an exec.
// A restart taken while a fence is held therefore does this:
//
//	the fence is discarded  ->  the allocator re-seeds from the highest
//	COMMITTED on-chain nonce, which is still BELOW N (that is exactly what
//	"unresolved" means)  ->  it issues some M in the gap  ->  M commits  ->  the
//	late N finally arrives and app-v9 rejects it Code 4.
//
// That loss is untraceable after the fact: the operator sees an unrelated later
// action fail as a replay. A crash or a SIGKILL can still do it to us — closing
// that needs durable pre-broadcast intent, which is deliberately not in this
// release. But the DOMINANT path into it is not a crash; it is this node
// deciding, on its own schedule, to restart for an update. That one we control,
// so we refuse it.
//
// NOTHING HERE MAY SUGGEST RESTARTING ANYWAY. There is no flag, no override and
// no operator advice to "restart to clear it", because restarting is the action
// that loses the transaction. The way out is reconciliation proving the
// transaction's fate, which internal/tx is actively driving by re-submitting the
// identical bytes.
//
// WHEN THE VETO RUNS MATTERS AS MUCH AS WHAT IT CHECKS. A check made only when
// the restart is REQUESTED is a time-of-check race: the drain that follows
// severs in-flight HTTP handlers after the shutdown budget, and a severed
// broadcast is precisely how an indeterminate outcome — a new fence — is
// manufactured, AFTER the only veto that ever ran. So the restart path in
// node.go checks three times:
//  1. at request time (prepareAndQueueRestart / RequestRestartPrepared), so a
//     doomed restart is refused before anything reversible is prepared;
//  2. when the restart is taken off the queue: signing is QUIESCED first, the
//     drain WAITS until no submission is in flight or queued
//     (tx.WaitForSigningIdle) — at which point every fence that was going to
//     exist already exists — and only then is the veto re-checked, while the
//     restart can still be abandoned and the node can keep serving;
//  3. after the full drain, as a last-resort tripwire for the adoption path
//     that never ran step 2: a fence held there fails the shutdown gate and
//     aborts the version transition instead of being exec'd over.
// Step 2 is the guarantee; steps 1 and 3 keep the cheap refusal cheap and the
// impossible case loud.

// signerFenceVeto reports why a coordinated restart must not proceed, or "" when
// there is nothing outstanding.
//
// It is a variable so tests can drive both answers and the fail-closed path
// without fencing a real signing key.
var signerFenceVeto = tx.RestartVetoReason

// errRestartVetoUnavailable is what a veto that cannot be evaluated returns.
// Deliberately its own error: "we could not check" and "we checked and a key is
// fenced" are different operator stories, and only the first one is a bug in
// this node rather than a transaction waiting on the chain.
var errRestartVetoUnavailable = errors.New(
	"the signer-fence restart guard could not be evaluated, so the restart was refused; " +
		"restarting without it risks losing a transaction whose outcome was never confirmed")

// checkSignerFenceRestartVeto returns a non-nil error when a coordinated restart
// must be refused.
//
// IT FAILS CLOSED, AND THAT IS THE ENTIRE POINT. A guard that quietly degrades
// to "proceed" when it malfunctions is worse than no guard at all, because the
// release notes will say the case is handled and nobody will look again. So an
// unwired hook is a veto, and a hook that panics is a veto — the node survives
// (an update refusing to install is recoverable; a lost transaction is not) but
// it does not restart.
func checkSignerFenceRestartVeto(veto func() string) (err error) {
	if veto == nil {
		return errRestartVetoUnavailable
	}
	defer func() {
		if r := recover(); r != nil {
			// Not %v of the recovered value: a panic value from the fence path
			// can be an error built from a broadcast URL, which carries the
			// whole signed transaction. The category is all a restart decision
			// needs anyway.
			err = fmt.Errorf("%w (the guard panicked)", errRestartVetoUnavailable)
		}
	}()
	if reason := veto(); reason != "" {
		return errors.New("restart refused: " + reason)
	}
	return nil
}

// commitRestartAfterSigningDrain is step 2 of the veto ordering above — the
// guarantee itself — extracted from the shutdown select so it can be tested:
// quiesce signing, wait for the in-flight population to reach zero (at which
// point every fence that was going to exist already exists), and only then
// re-evaluate the veto, while the restart can still be abandoned and the node
// can keep serving.
//
// A nil return COMMITS the restart: the drain preparation's commit has run and
// signing is deliberately left quiesced — a transaction signed into the
// teardown that follows is the likeliest in the process's life to end with an
// unobserved fate, which is exactly what the in-process fence cannot carry
// across the exec. prepared keeps its release func for the caller's version
// transition bookkeeping.
//
// A non-nil return ABANDONS it, fail closed, and the ordering of the unwind is
// part of the contract:
//  1. abort() — undo the reversible drain preparation (snapshot scheduler
//     quiesce, pinned recovery binary) before anything else, so the node is
//     back to serving shape;
//  2. release() — let go of the preflight fence the updater handed over;
//  3. reset *prepared to zero — the shutdown path later ADOPTS whatever request
//     is left populated (adoptQueuedRestartRequests), so a stale abort/release
//     here would be double-run on the next signal;
//  4. resume signing — LAST, and unconditionally, or an abandoned restart
//     leaves the node permanently refusing every signing request with
//     ErrSigningQuiesced until a real restart, which is an outage with no
//     fence behind it.
func commitRestartAfterSigningDrain(prepared *preparedRestartRequest, veto func() string, idleBudget time.Duration) error {
	resumeSigning := tx.QuiesceSigningForRestart()
	idleCtx, cancelIdle := context.WithTimeout(context.Background(), idleBudget)
	idleErr := tx.WaitForSigningIdle(idleCtx)
	cancelIdle()
	vetoErr := idleErr
	if vetoErr == nil {
		vetoErr = checkSignerFenceRestartVeto(veto)
	}
	if vetoErr != nil {
		if prepared.abort != nil {
			prepared.abort()
		}
		if prepared.release != nil {
			prepared.release()
		}
		*prepared = preparedRestartRequest{}
		resumeSigning()
		return vetoErr
	}
	if prepared.commit != nil {
		prepared.commit()
	}
	return nil
}
