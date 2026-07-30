package abci

import (
	"fmt"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

const appV24MemoryHashReanchorOperationName = "memory_hash_reanchor"

type appV24MemoryHashReanchorValidation struct {
	payload *tx.MemoryHashReanchorPayload
	entries []store.MemoryHashReanchorEntry
}

// validateAppV24MemoryHashReanchorProposal binds all proposal fields to the
// current Root generation and, when validateEligibility is true, rechecks the
// entire repair population against one read-only Badger snapshot. Callers use
// the latter form from ProcessBlockValidated immediately before governance
// marks the proposal executed.
func (app *SageApp) validateAppV24MemoryHashReanchorProposal(
	proposal *governance.ProposalState,
	height int64,
	validateEligibility bool,
) (*appV24MemoryHashReanchorValidation, error) {
	if proposal == nil {
		return nil, fmt.Errorf("memory hash reanchor proposal is required")
	}
	if proposal.Operation != governance.OpMemoryHashReanchor {
		return nil, fmt.Errorf(
			"memory hash reanchor validation received operation %d",
			proposal.Operation,
		)
	}
	return app.validateAppV24MemoryHashReanchorFields(
		proposal.TargetID,
		proposal.TargetPubKey,
		proposal.TargetPower,
		proposal.Payload,
		height,
		validateEligibility,
	)
}

func (app *SageApp) validateAppV24MemoryHashReanchorFields(
	targetID string,
	targetPubKey []byte,
	targetPower int64,
	payloadBytes []byte,
	height int64,
	validateEligibility bool,
) (*appV24MemoryHashReanchorValidation, error) {
	if !app.postAppV24Rules(height) {
		return nil, fmt.Errorf("memory hash reanchor requires app-v24")
	}
	if len(targetPubKey) != 0 {
		return nil, fmt.Errorf("memory hash reanchor target_pubkey must be empty")
	}
	if targetPower != 0 {
		return nil, fmt.Errorf("memory hash reanchor target_power must be zero")
	}

	payload, err := tx.DecodeMemoryHashReanchorPayload(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("decode memory hash reanchor payload: %w", err)
	}
	expectedTargetID, err := tx.MemoryHashReanchorTargetID(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("derive memory hash reanchor target: %w", err)
	}
	if targetID != expectedTargetID {
		return nil, fmt.Errorf("memory hash reanchor target_id does not match payload")
	}

	root, err := app.badgerStore.GetAppV23Root()
	if err != nil {
		return nil, fmt.Errorf("read current Root for memory hash reanchor: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("current Root is unavailable")
	}
	if payload.RootCredentialID != root.CredentialID ||
		payload.RootGeneration != root.Generation {
		return nil, fmt.Errorf(
			"memory hash reanchor Root binding is stale or does not match the current Root generation",
		)
	}

	entries := make([]store.MemoryHashReanchorEntry, len(payload.Entries))
	for i, entry := range payload.Entries {
		entries[i] = store.MemoryHashReanchorEntry{
			MemoryID:       entry.MemoryID,
			ExpectedStatus: entry.ExpectedStatus,
			ContentHash:    append([]byte(nil), entry.ContentHash...),
		}
	}
	if validateEligibility {
		if err := app.badgerStore.ValidateMemoryHashReanchors(entries); err != nil {
			return nil, fmt.Errorf("memory hash reanchor eligibility: %w", err)
		}
	}
	return &appV24MemoryHashReanchorValidation{
		payload: payload,
		entries: entries,
	}, nil
}

func (app *SageApp) requireCurrentRootMemoryHashReanchorAuthorizer(
	authorizerID string,
) error {
	root, err := app.badgerStore.GetAppV23Root()
	if err != nil {
		return fmt.Errorf("read current Root for memory hash reanchor authorization: %w", err)
	}
	if root == nil || authorizerID != root.CredentialID {
		return fmt.Errorf("only the exact current Root credential can authorize memory hash reanchor")
	}
	return nil
}

// applyMemoryHashReanchor executes one already-approved repair chunk. It
// rechecks the immutable payload/target/Root binding, then delegates the
// complete eligibility-and-write operation to one atomic Badger primitive.
func (app *SageApp) applyMemoryHashReanchor(
	proposal *governance.ProposalState,
	height int64,
) error {
	validated, err := app.validateAppV24MemoryHashReanchorProposal(
		proposal, height, false,
	)
	if err != nil {
		return err
	}
	if err := app.badgerStore.ReanchorMemoryHashes(validated.entries); err != nil {
		return fmt.Errorf("apply memory hash reanchor: %w", err)
	}
	app.logger.Info().
		Str("proposal_id", proposal.ProposalID).
		Int("entries", len(validated.payload.Entries)).
		Int64("height", height).
		Msg("app-v24 memory hash reanchor applied")
	return nil
}
