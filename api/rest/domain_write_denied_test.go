package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l33tdawg/sage/internal/authzdenial"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubmitMemoryEffectiveWriteDenialMatrix(t *testing.T) {
	tests := []struct {
		name string
		log  string
		code authzdenial.Code
	}{
		{"missing write grant", "access denied: denial_code=missing_write_grant", authzdenial.CodeMissingWriteGrant},
		{"foreign write bit 8", "access denied: denial_code=foreign_write_restricted", authzdenial.CodeForeignWriteRestricted},
		{"shared write bit 2", "access denied: denial_code=shared_write_restricted", authzdenial.CodeSharedWriteRestricted},
		{"domain claim bit 4", "access denied: denial_code=domain_claim_restricted", authzdenial.CodeDomainClaimRestricted},
		{"principal pending review", "access denied: denial_code=principal_pending_review", authzdenial.CodePrincipalPendingReview},
		{"no owned home", "access denied: denial_code=no_owned_home_domain", authzdenial.CodeNoOwnedHomeDomain},
		{"manager scope", "access denied: denial_code=manager_scope_denied", authzdenial.CodeManagerScopeDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeCometCommitFixture(t, w, r, 0, "", 11, test.log, 1)
			}))
			defer cometMock.Close()

			srv, _, _ := newTestServer(t, cometMock.URL)
			body := []byte(`{"content":"domain ACL regression","memory_type":"fact","domain_tag":"fa-pillar","confidence_score":0.9}`)
			req, _ := signedRequest(t, http.MethodPost, "/v1/memory/submit", body)
			rr := httptest.NewRecorder()
			srv.Router().ServeHTTP(rr, req)

			require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			var problem struct {
				Type       string `json:"type"`
				Title      string `json:"title"`
				Detail     string `json:"detail"`
				ReasonCode string `json:"reason_code"`
				Remedy     string `json:"remedy"`
				Retryable  *bool  `json:"retryable"`
			}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &problem))
			assert.Equal(t, authzdenial.ProblemTypeURI, problem.Type)
			assert.Equal(t, "Memory write access denied", problem.Title)
			assert.Equal(t, string(test.code), problem.ReasonCode)
			definition, ok := authzdenial.Definition(test.code)
			require.True(t, ok)
			assert.Equal(t, definition.Remedy, problem.Remedy)
			require.NotNil(t, problem.Retryable)
			assert.False(t, *problem.Retryable)
			assert.Equal(t, "This memory write is blocked by effective access policy.", problem.Detail)
			assert.NotContains(t, rr.Body.String(), "LEAK-AGENT")
			assert.NotContains(t, rr.Body.String(), "LEAK-DOMAIN")
			assert.NotContains(t, rr.Body.String(), "fa-pillar")
		})
	}
}

func TestSubmitMemoryLegacyDenialUsesCanonicalPublicCode(t *testing.T) {
	cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCometCommitFixture(t, w, r, 0, "", 11,
			"access denied: agent 0123456789abcdef cannot write domain private it does not own", 1)
	}))
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	body := []byte(`{"content":"legacy denial regression","memory_type":"fact","domain_tag":"fa-pillar","confidence_score":0.9}`)
	req, _ := signedRequest(t, http.MethodPost, "/v1/memory/submit", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	var problem map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &problem))
	assert.Equal(t, authzdenial.ProblemTypeURI, problem["type"])
	assert.Equal(t, string(authzdenial.CodeForeignWriteRestricted), problem["reason_code"])
	assert.NotContains(t, rr.Body.String(), "0123456789abcdef")
	assert.NotContains(t, rr.Body.String(), "private")
}

func TestSubmitMemoryUnknownOrControlPlaneDenialRemainsOpaqueAndUntyped(t *testing.T) {
	for _, log := range []string{
		"access denied: internal LEAK-DIAGNOSTIC",
		"access denied: denial_code=control_plane_denied",
		"access denied: denial_code=future_code cannot write shared domain LEAK-DOMAIN",
	} {
		t.Run(log, func(t *testing.T) {
			cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeCometCommitFixture(t, w, r, 0, "", 11, log, 1)
			}))
			defer cometMock.Close()

			srv, _, _ := newTestServer(t, cometMock.URL)
			body := []byte(`{"content":"opaque denial regression","memory_type":"fact","domain_tag":"fa-pillar","confidence_score":0.9}`)
			req, _ := signedRequest(t, http.MethodPost, "/v1/memory/submit", body)
			rr := httptest.NewRecorder()
			srv.Router().ServeHTTP(rr, req)

			require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			var problem map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &problem))
			assert.Equal(t, "https://sage.dev/errors/403", problem["type"])
			assert.NotContains(t, problem, "reason_code")
			assert.NotContains(t, problem, "remedy")
			assert.NotContains(t, rr.Body.String(), "LEAK-DIAGNOSTIC")
			assert.NotContains(t, rr.Body.String(), "LEAK-DOMAIN")
		})
	}
}

func TestWriteEffectiveWriteDenialRejectsUnknownCode(t *testing.T) {
	rr := httptest.NewRecorder()
	writeEffectiveWriteDenial(rr, authzdenial.EffectiveWriteDenial{
		Code:      "control_plane_denied",
		Remedy:    "untrusted remedy",
		Retryable: false,
	})

	require.Equal(t, http.StatusForbidden, rr.Code)
	var problem map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &problem))
	assert.Equal(t, "https://sage.dev/errors/403", problem["type"])
	assert.NotContains(t, problem, "reason_code")
	assert.NotContains(t, problem, "remedy")
	assert.NotContains(t, rr.Body.String(), "untrusted remedy")
}

func TestAppV23RESTPreflightMatchesConsensusWriteDenialTaxonomy(t *testing.T) {
	assertCode := func(t *testing.T, err error, expected authzdenial.Code) {
		t.Helper()
		require.Error(t, err)
		denial, ok := authzdenial.Classify(err)
		require.True(t, ok, "untyped preflight denial: %v", err)
		require.Equal(t, expected, denial.Code)
	}
	rootID := appV23RESTAgentID("11")

	t.Run("missing write grant", func(t *testing.T) {
		server, _, _, _, outsiderID := setupAppV23RESTAccess(t)
		assertCode(t, server.checkDomainAccess(
			context.Background(), outsiderID, "owner.home", "write",
		), authzdenial.CodeMissingWriteGrant)
	})

	t.Run("foreign write restricted", func(t *testing.T) {
		server, badger, memberID, _, _ := setupAppV23RESTAccess(t)
		enrollment, err := badger.GetAppV23Enrollment(memberID)
		require.NoError(t, err)
		role, err := badger.GetAppV23Role(memberID)
		require.NoError(t, err)
		require.NoError(t, badger.SetAppV23Policy(
			rootID, memberID, store.AppV23RoleMember,
			enrollment.Profile, store.AppV23ProfileCompanion, enrollment.Clearance,
			15, role.Revision, enrollment.Revision, 5,
		))
		assertCode(t, server.checkDomainAccess(
			context.Background(), memberID, "owner.home", "write",
		), authzdenial.CodeForeignWriteRestricted)
	})

	t.Run("dynamic shared write restricted", func(t *testing.T) {
		server, badger, memberID, _, _ := setupAppV23RESTAccess(t)
		enrollment, err := badger.GetAppV23Enrollment(memberID)
		require.NoError(t, err)
		role, err := badger.GetAppV23Role(memberID)
		require.NoError(t, err)
		require.NoError(t, badger.SetAppV23Policy(
			rootID, memberID, store.AppV23RoleMember,
			enrollment.Profile, store.AppV23ProfileCompanion, enrollment.Clearance,
			15, role.Revision, enrollment.Revision, 5,
		))
		require.NoError(t, badger.SetState("shared_domain:team-lounge", []byte("1")))
		assertCode(t, server.checkDomainAccess(
			context.Background(), memberID, "team-lounge", "write",
		), authzdenial.CodeSharedWriteRestricted)
	})

	t.Run("domain claim restricted", func(t *testing.T) {
		server, badger, _, _, outsiderID := setupAppV23RESTAccess(t)
		enrollment, err := badger.GetAppV23Enrollment(outsiderID)
		require.NoError(t, err)
		role, err := badger.GetAppV23Role(outsiderID)
		require.NoError(t, err)
		require.NoError(t, badger.SetAppV23Policy(
			rootID, outsiderID, store.AppV23RoleMember,
			enrollment.Profile, store.AppV23ProfileCompanion,
			enrollment.Clearance, 15,
			role.Revision, enrollment.Revision, 5,
		))
		assertCode(t, server.checkDomainAccess(
			context.Background(), outsiderID, "unowned-domain", "write",
		), authzdenial.CodeDomainClaimRestricted)
	})

	t.Run("principal pending review", func(t *testing.T) {
		server, badger, _, _, _ := setupAppV23RESTAccess(t)
		pendingID := appV23RESTAgentID("99")
		require.NoError(t, badger.RegisterAgent(
			pendingID, "pending", store.AppV23RoleMember, "", "test", "", 5,
		))
		assertCode(t, server.checkDomainAccess(
			context.Background(), pendingID, "owner.home", "write",
		), authzdenial.CodePrincipalPendingReview)
	})

	t.Run("no owned home domain", func(t *testing.T) {
		server, badger, memberID, _, _ := setupAppV23RESTAccess(t)
		require.NoError(t, badger.SetState("shared_domain:member.home", []byte("1")))
		assertCode(t, server.checkDomainAccess(
			context.Background(), memberID, "owner.home", "write",
		), authzdenial.CodeNoOwnedHomeDomain)
	})

	t.Run("manager scope denied", func(t *testing.T) {
		server, badger, _, _, outsiderID := setupAppV23RESTAccess(t)
		enrollment, err := badger.GetAppV23Enrollment(outsiderID)
		require.NoError(t, err)
		role, err := badger.GetAppV23Role(outsiderID)
		require.NoError(t, err)
		require.NoError(t, badger.SetAppV23Policy(
			rootID, outsiderID, store.AppV23RoleManager,
			enrollment.Profile, store.AppV23ProfileStandard, enrollment.Clearance,
			0, role.Revision, enrollment.Revision, 5,
		))
		assertCode(t, server.checkDomainAccess(
			context.Background(), outsiderID, "owner.home", "write",
		), authzdenial.CodeManagerScopeDenied)
	})
}
