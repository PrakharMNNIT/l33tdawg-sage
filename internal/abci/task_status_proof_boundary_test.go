package abci

import (
	"crypto/sha256"
	"testing"

	"github.com/l33tdawg/sage/internal/tx"
	"github.com/stretchr/testify/require"
)

// THE CONSENSUS BOUNDARY THIS PINS.
//
// A signed task submission binds task_status. If the client omits it, the
// signed body carries no status while the node broadcasts one — REST used to
// default the omission to "planned" AFTER the signature covered the request —
// and the reconstruction below rejects the pair. That rejection is CORRECT and
// must stay correct through app-v26.
//
// This is a read-only guard on that boundary, with no production change. It
// exists because the clients were fixed to send the field explicitly and REST
// now rejects an omission at the edge, which means nothing reaching consensus
// exercises this path any more. The risk that creates is the opposite of the
// original bug: a future change could teach the proof check to normalize an
// omitted status server-side and nothing would notice. That would be an
// UNGATED CONSENSUS CHANGE — nodes on different versions would disagree about
// whether the same transaction validates, which is a fork.
//
// App-v27 normalizes this only behind its forward gate. Before that boundary,
// omission must remain a mismatch.
func TestAppV26TaskStatusOmissionStaysAProofMismatch(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	content := "[TASK] pin the consensus boundary"
	contentHash := sha256.Sum256([]byte(content))

	// The agent signs a task WITHOUT task_status.
	omitted := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content": content, "memory_type": "task", "confidence_score": 0.9,
	})
	omittedReq, err := parseSignedAgentRequest(omitted)
	require.NoError(t, err)

	// The node broadcasts one carrying "planned" — exactly what the old REST
	// default produced after the signature was already fixed.
	broadcast := &tx.ParsedTx{Type: tx.TxTypeMemorySubmit, MemorySubmit: &tx.MemorySubmit{
		MemoryID: "00000000-0000-4000-8000-000000000000", ContentHash: contentHash[:],
		MemoryType: tx.MemoryTypeTask, DomainTag: "voice-interface",
		ConfidenceScore: 0.9, Content: content, TaskStatus: "planned",
	}}

	err = app.verifySignedAgentAction(broadcast, companion.id, omittedReq, false, true, true, false)
	require.Error(t, err,
		"an omitted signed task_status must NOT be normalized by the proof check; "+
			"accepting it would change which transactions validate, which is fork-class")
}

// The converse, so the guard above cannot be satisfied by a proof check that
// simply rejects everything: an EXPLICITLY signed "planned" must still verify.
func TestAppV26ExplicitPlannedTaskStatusStillVerifies(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	content := "[TASK] explicit planned still verifies"
	contentHash := sha256.Sum256([]byte(content))

	explicit := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content": content, "memory_type": "task", "confidence_score": 0.9,
		"task_status": "planned",
	})
	explicitReq, err := parseSignedAgentRequest(explicit)
	require.NoError(t, err)

	broadcast := &tx.ParsedTx{Type: tx.TxTypeMemorySubmit, MemorySubmit: &tx.MemorySubmit{
		MemoryID: "00000000-0000-4000-8000-000000000000", ContentHash: contentHash[:],
		MemoryType: tx.MemoryTypeTask, DomainTag: "voice-interface",
		ConfidenceScore: 0.9, Content: content, TaskStatus: "planned",
	}}

	require.NoError(t,
		app.verifySignedAgentAction(broadcast, companion.id, explicitReq, false, true, true, false),
		"an explicitly signed planned status is what every fixed client now sends; "+
			"it must verify, or the clients are broken instead")
}

func TestAppV27TaskStatusOmissionNormalizesToPlanned(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	content := "[TASK] app-v27 canonical omitted status"
	contentHash := sha256.Sum256([]byte(content))

	omitted := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content": content, "memory_type": "task", "confidence_score": 0.9,
	})
	omittedReq, err := parseSignedAgentRequest(omitted)
	require.NoError(t, err)

	broadcast := &tx.ParsedTx{Type: tx.TxTypeMemorySubmit, MemorySubmit: &tx.MemorySubmit{
		MemoryID: "00000000-0000-4000-8000-000000000000", ContentHash: contentHash[:],
		MemoryType: tx.MemoryTypeTask, DomainTag: "voice-interface",
		ConfidenceScore: 0.9, Content: content, TaskStatus: "planned",
	}}

	require.NoError(t,
		app.verifySignedAgentAction(broadcast, companion.id, omittedReq, false, true, true, true),
		"post-app-v27 treats omitted task_status as the canonical initial planned status")
}

func TestAppV27ExplicitEmptyTaskStatusIsNotOmission(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	content := "[TASK] explicit empty is invalid"
	contentHash := sha256.Sum256([]byte(content))
	explicitEmpty := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content": content, "memory_type": "task", "confidence_score": 0.9,
		"task_status": "",
	})
	req, err := parseSignedAgentRequest(explicitEmpty)
	require.NoError(t, err)
	broadcast := &tx.ParsedTx{Type: tx.TxTypeMemorySubmit, MemorySubmit: &tx.MemorySubmit{
		MemoryID: "00000000-0000-4000-8000-000000000000", ContentHash: contentHash[:],
		MemoryType: tx.MemoryTypeTask, DomainTag: "voice-interface",
		ConfidenceScore: 0.9, Content: content, TaskStatus: "planned",
	}}
	require.Error(t,
		app.verifySignedAgentAction(broadcast, companion.id, req, false, true, true, true),
		"an explicitly signed empty status must not acquire omission semantics")
}

func TestAppV27NullTaskStatusIsNotOmission(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	content := "[TASK] null is not omission"
	contentHash := sha256.Sum256([]byte(content))
	nullStatus := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content": content, "memory_type": "task", "confidence_score": 0.9,
		"task_status": nil,
	})
	req, err := parseSignedAgentRequest(nullStatus)
	require.NoError(t, err)
	broadcast := &tx.ParsedTx{Type: tx.TxTypeMemorySubmit, MemorySubmit: &tx.MemorySubmit{
		MemoryID: "00000000-0000-4000-8000-000000000000", ContentHash: contentHash[:],
		MemoryType: tx.MemoryTypeTask, DomainTag: "voice-interface",
		ConfidenceScore: 0.9, Content: content, TaskStatus: "planned",
	}}
	require.ErrorContains(t,
		app.verifySignedAgentAction(broadcast, companion.id, req, false, true, true, true),
		"must be a string")
}

func TestPreAppV27NullTaskStatusPreservesHistoricalEmptyDecode(t *testing.T) {
	app := setupTestApp(t)
	content := "historical explicit null task status"
	contentHash := sha256.Sum256([]byte(content))
	nullStatus := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content": content, "memory_type": "fact", "domain_tag": "research",
		"confidence_score": 0.9, "task_status": nil,
	})
	req, err := parseSignedAgentRequest(nullStatus)
	require.NoError(t, err)
	broadcast := &tx.ParsedTx{Type: tx.TxTypeMemorySubmit, MemorySubmit: &tx.MemorySubmit{
		MemoryID: "00000000-0000-4000-8000-000000000000", ContentHash: contentHash[:],
		MemoryType: tx.MemoryTypeFact, DomainTag: "research",
		ConfidenceScore: 0.9, Content: content,
	}}
	require.NoError(t,
		app.verifySignedAgentAction(broadcast, "delegated-agent", req, false, false, false, false),
		"pre-app-v27 replay must preserve encoding/json's historical null-to-empty string decode")
}
