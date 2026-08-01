package rest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV25RecoveredOwnerTransferMatchesRESTAuthorization(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	rootID := fmt.Sprintf("%064x", 9701)
	ownerID := fmt.Sprintf("%064x", 9799)
	memberID := fmt.Sprintf("%064x", 9702)
	newOwnerID := fmt.Sprintf("%064x", 9703)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		rootID, "root", store.AppV23RoleAdmin, "", "", "", 4, 0,
	))
	for _, writer := range []string{ownerID, memberID} {
		require.NoError(t, badger.RegisterAgentWithCapabilities(
			writer, writer, store.AppV23RoleMember, "", "", "", 2,
			store.DefaultSelfRegisteredAgentCapabilities,
		))
	}
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		newOwnerID, "new-owner", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	// Freeze an H-1 domain allowlist that omits the recovered domain. A normal
	// level-1 grant must not bypass this restriction, but a later Root-governed
	// ownership transfer must not leave the new owner able to write but unable
	// to read/list the same memory.
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		newOwnerID, 2,
		`[{"domain":"different-preupgrade-domain","read":true}]`,
		"*", "", "", 0,
	))
	const domain = "recovered-owner-rest"
	require.NoError(t, badger.RegisterDomain(domain, rootID, "", 5))
	require.NoError(t, badger.EnsureAppV23Root("recovered-owner-rest", 100))
	writers := []string{ownerID, memberID}
	sort.Strings(writers)
	plan := sha256.Sum256([]byte("recovered-owner-rest-plan"))
	require.NoError(t, badger.ApplyAppV25DomainContinuityBatch(
		[]store.AppV25DomainContinuityBatchEntry{{
			Domain: domain, Owner: ownerID, Writers: writers,
		}},
		plan[:], 1, 120,
	))

	check := func(agentID, verb string, want bool) {
		t.Helper()
		err := srv.checkDomainAccess(context.Background(), agentID, domain, verb)
		if want {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	check(ownerID, "read", true)
	check(ownerID, "write", true)
	check(ownerID, "modify", true)
	check(memberID, "read", true)
	check(memberID, "write", true)
	check(memberID, "modify", false)

	require.NoError(t, badger.TransferDomainAppV23(
		domain, newOwnerID, "", 121, false,
	))
	check(ownerID, "read", true)
	check(ownerID, "write", true)
	check(ownerID, "modify", false)
	check(newOwnerID, "read", true)
	check(newOwnerID, "write", true)
	check(newOwnerID, "modify", true)
	for _, agentID := range []string{ownerID, memberID, newOwnerID} {
		allowed, err := srv.hasMemoryReadAccess(
			domain, agentID, 1, time.Unix(1000, 0),
		)
		require.NoError(t, err)
		require.Truef(t, allowed, "agent %s", agentID)
	}
	record := &memory.MemoryRecord{
		MemoryID: "recovered-owner-readback", SubmittingAgent: ownerID,
		Content: "governed owner must read this back", MemoryType: memory.TypeFact,
		DomainTag: domain, ConfidenceScore: 0.9, Status: memory.StatusCommitted,
	}
	record.ContentHash = memory.ComputeContentHash(record.Content)
	publishAppV23RESTRecord(t, badger, record, 1)
	disclosure, err := srv.evaluateAppV23RecordDisclosure(
		newOwnerID, record, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, disclosure.Allowed,
		"current governed ownership must override an H-1 domain omission on record disclosure")
}
