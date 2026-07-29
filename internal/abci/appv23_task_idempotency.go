package abci

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/taskidempotency"
	"github.com/l33tdawg/sage/internal/tx"
)

type appV23TaskIdempotencyIntent struct {
	key      string
	binding  *store.AppV23TaskIdempotencyBinding
	isReplay bool
}

func (app *SageApp) appV23TaskIdempotencyForSubmit(
	parsed *tx.ParsedTx,
	principalID, assigneeID string,
	height int64,
) (*appV23TaskIdempotencyIntent, error) {
	if !app.postAppV23Rules(height) || parsed == nil || parsed.MemorySubmit == nil ||
		parsed.MemorySubmit.MemoryType != tx.MemoryTypeTask {
		return nil, nil
	}
	if len(parsed.AgentRequest) == 0 {
		return nil, nil
	}
	request, requestErr := parseSignedAgentRequest(parsed.AgentRequest)
	if requestErr != nil {
		return nil, requestErr
	}
	if _, routeErr := requireAgentRoute(request, "POST", "v1", "memory", "submit"); routeErr != nil {
		return nil, routeErr
	}
	var body struct {
		IdempotencyKey string `json:"idempotency_key,omitempty"`
	}
	if decodeErr := json.Unmarshal(request.body, &body); decodeErr != nil {
		return nil, fmt.Errorf("decode signed task idempotency request: %w", decodeErr)
	}
	if body.IdempotencyKey == "" {
		semanticKey, semanticErr := taskidempotency.SemanticKey(
			assigneeID,
			parsed.MemorySubmit.DomainTag,
			parsed.MemorySubmit.Content,
		)
		if semanticErr != nil {
			return nil, semanticErr
		}
		body.IdempotencyKey = semanticKey
	}
	if validationErr := taskidempotency.ValidateKey(body.IdempotencyKey); validationErr != nil {
		return nil, validationErr
	}
	if parsed.MemorySubmit.TaskStatus != "planned" {
		return nil, errors.New("idempotent app-v23 task must start as planned")
	}
	memoryID, memoryIDErr := taskidempotency.MemoryID(principalID, body.IdempotencyKey)
	if memoryIDErr != nil {
		return nil, memoryIDErr
	}
	if parsed.MemorySubmit.MemoryID != memoryID {
		return nil, errors.New("task memory_id does not match its principal-bound idempotency key")
	}
	payloadDigest, payloadErr := taskidempotency.PayloadDigest(
		principalID, assigneeID, parsed.MemorySubmit,
	)
	if payloadErr != nil {
		return nil, payloadErr
	}
	encoded, encodeErr := tx.EncodeTx(parsed)
	if encodeErr != nil {
		return nil, fmt.Errorf("encode task transaction for idempotency receipt: %w", encodeErr)
	}
	txHash := sha256.Sum256(encoded)
	keyDigest, digestErr := taskidempotency.BindingKeyDigest(principalID, body.IdempotencyKey)
	if digestErr != nil {
		return nil, digestErr
	}
	candidate := &store.AppV23TaskIdempotencyBinding{
		Version:          1,
		PrincipalID:      principalID,
		BindingKeyDigest: taskidempotency.Hex(keyDigest),
		PayloadDigest:    taskidempotency.Hex(payloadDigest),
		MemoryID:         memoryID,
		AssigneeID:       assigneeID,
		CommittedHeight:  height,
		TxHash:           strings.ToUpper(hex.EncodeToString(txHash[:])),
	}
	existing, bindingErr := app.badgerStore.GetAppV23TaskIdempotencyBinding(
		principalID, body.IdempotencyKey,
	)
	if bindingErr != nil {
		return nil, bindingErr
	}
	if existing == nil {
		return &appV23TaskIdempotencyIntent{
			key:     body.IdempotencyKey,
			binding: candidate,
		}, nil
	}
	if existing.PrincipalID != candidate.PrincipalID ||
		existing.PayloadDigest != candidate.PayloadDigest ||
		existing.MemoryID != candidate.MemoryID ||
		existing.AssigneeID != candidate.AssigneeID {
		return nil, store.ErrAppV23TaskIdempotencyConflict
	}
	if verifyErr := app.verifyAppV23TaskIdempotencyRecord(existing, parsed.MemorySubmit); verifyErr != nil {
		return nil, verifyErr
	}
	return &appV23TaskIdempotencyIntent{
		key:      body.IdempotencyKey,
		binding:  existing,
		isReplay: true,
	}, nil
}

func (app *SageApp) verifyAppV23TaskIdempotencyRecord(
	binding *store.AppV23TaskIdempotencyBinding,
	submit *tx.MemorySubmit,
) error {
	contentHash, _, err := app.badgerStore.GetMemoryHash(binding.MemoryID)
	if err != nil {
		return fmt.Errorf("idempotency binding references missing memory: %w", err)
	}
	if !bytes.Equal(contentHash, submit.ContentHash) {
		return errors.New("idempotency binding memory content hash mismatch")
	}
	domain, err := app.badgerStore.GetMemoryDomain(binding.MemoryID)
	if err != nil || domain != submit.DomainTag {
		return errors.New("idempotency binding memory domain mismatch")
	}
	classification, err := app.badgerStore.GetMemoryClassification(binding.MemoryID)
	if err != nil || classification != uint8(submit.Classification) {
		return errors.New("idempotency binding memory classification mismatch")
	}
	principalID, err := app.badgerStore.GetMemoryAuthorPrincipal(binding.MemoryID)
	if err != nil || principalID != binding.PrincipalID {
		return errors.New("idempotency binding memory principal mismatch")
	}
	return nil
}
