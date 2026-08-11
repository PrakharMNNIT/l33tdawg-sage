package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

// TestHandleSynapses drives the endpoint end to end over an in-memory store: bus
// messages aggregate into directed weighted synapses in the JSON body, and the
// response carries the {neurons, synapses} connectome shape. With no BadgerStore
// the caller is a human dashboard (seeAll), so no RBAC filtering applies and
// neurons are empty (no on-chain registry attached).
func TestHandleSynapses(t *testing.T) {
	h, s := newTestHandler(t)
	ctx := context.Background()

	base := time.Now().UTC().Truncate(time.Second)
	mk := func(id, from, to string, at time.Time) *store.PipelineMessage {
		return &store.PipelineMessage{
			PipeID: id, FromAgent: from, ToAgent: to,
			Payload: "hi", Status: "pending",
			CreatedAt: at, ExpiresAt: at.Add(time.Hour),
		}
	}
	require.NoError(t, s.InsertPipeline(ctx, mk("p1", "alice", "bob", base)))
	require.NoError(t, s.InsertPipeline(ctx, mk("p2", "alice", "bob", base.Add(time.Minute))))
	require.NoError(t, s.InsertPipeline(ctx, mk("p3", "bob", "alice", base)))

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil)
	rec := httptest.NewRecorder()
	h.handleSynapses(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body struct {
		Neurons  []map[string]any    `json:"neurons"`
		Synapses []store.PipeSynapse `json:"synapses"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotNil(t, body.Neurons, "neurons is an array, never null")
	require.NotNil(t, body.Synapses, "synapses is an array, never null")

	byEdge := make(map[string]store.PipeSynapse, len(body.Synapses))
	for _, e := range body.Synapses {
		byEdge[e.FromAgent+"|"+e.ToAgent] = e
	}
	require.Len(t, body.Synapses, 2, "two directed synapses")
	require.Equal(t, int64(2), byEdge["alice|bob"].Count, "weight = message count")
	require.Equal(t, int64(1), byEdge["bob|alice"].Count)
	require.NotEmpty(t, byEdge["alice|bob"].LastFired)
}
