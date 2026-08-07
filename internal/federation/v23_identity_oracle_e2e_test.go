package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

func enrollV23SourceReadAllAdmin(
	t *testing.T,
	source *testChain,
	name string,
	pub ed25519.PublicKey,
	height int64,
) {
	t.Helper()
	agentID := hex.EncodeToString(pub)
	if err := source.badger.RegisterAgentWithCapabilities(
		agentID,
		name,
		store.AppV23RoleMember,
		"",
		"identity-oracle",
		"",
		height,
		store.DefaultSelfRegisteredAgentCapabilities,
	); err != nil {
		t.Fatal(err)
	}
	root, err := source.badger.GetAppV23Root()
	if err != nil || root == nil {
		t.Fatalf("source Root: state=%+v err=%v", root, err)
	}
	if err := source.badger.ApproveAppV23LocalAgent(store.AppV23LocalEnrollment{
		AgentID:        agentID,
		ApprovedBy:     root.CredentialID,
		RootGeneration: root.Generation,
		Profile:        store.AppV23ProfileStandard,
		HomeDomain:     "local-" + agentID,
		Clearance:      4,
		Capabilities:   store.AgentCapabilityReadAllDomains,
		Active:         true,
		UpdatedHeight:  height + 1,
	}, store.AppV23RoleAdmin, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func planV23QueryForAgent(
	t *testing.T,
	source, destination *testChain,
	agentID, domain string,
) *RecallPlan {
	t.Helper()
	plan, err := source.mgr.PlanRecall(
		context.Background(),
		[]string{destination.chainID},
		agentID,
		domain,
	)
	if err != nil {
		t.Fatalf("plan recall for %s: %v", agentID, err)
	}
	if len(plan.Destinations) != 1 || plan.Destinations[0] != destination.chainID {
		t.Fatalf("plan recall for %s: %+v", agentID, plan)
	}
	return plan
}

func signV23QueryAs(
	t *testing.T,
	agentKey ed25519.PrivateKey,
	plan *RecallPlan,
	request *QueryRequest,
) *QueryRequest {
	t.Helper()
	path := "/v1/memory/search"
	switch request.Mode {
	case ModeSemantic:
		path = "/v1/memory/query"
	case ModeHybrid:
		path = "/v1/memory/hybrid"
	}
	signedBody := map[string]any{
		"query": request.Query, "embedding": request.Embedding,
		"domain_tag": request.DomainTag, "provider": request.Provider,
		"min_confidence": request.MinConfidence, "top_k": request.TopK,
		"tags": request.Tags, "federated": true,
		"federate_chains": plan.Destinations,
		"federation_context": map[string]any{
			"source_chain_id":            plan.SourceChainID,
			"agreement_bindings":         plan.AgreementBindings,
			"query_challenges":           plan.QueryChallenges,
			"authorization_models":       plan.AuthorizationModels,
			"authorization_attestations": plan.AuthorizationAttestations,
		},
	}
	if request.EmbeddingProvider != "" {
		signedBody["embedding_provider"] = request.EmbeddingProvider
	}
	body, err := json.Marshal(signedBody)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	pub := agentKey.Public().(ed25519.PublicKey)
	request.AgentProof = &QueryAgentProof{
		AgentID: hex.EncodeToString(pub),
		Signature: auth.SignRequestWithNonce(
			agentKey, http.MethodPost, path, body, now, nonce,
		),
		Timestamp:        now,
		Nonce:            nonce,
		CanonicalRequest: append([]byte("POST "+path+"\n"), body...),
	}
	request.PlanAgreementBindings = plan.AgreementBindings
	request.PlanChallenges = plan.QueryChallenges
	request.PlanAuthorizationModels = plan.AuthorizationModels
	request.PlanAuthorizationAttestations = plan.AuthorizationAttestations
	return request
}

func TestV23FederatedGuestIdentityOracleOverTwoSAGEMTLS(t *testing.T) {
	source := newTestChain(t, "identity-source")
	destination := newTestChain(t, "identity-destination")
	agentXPub, agentXKey, agentXKeyErr := ed25519.GenerateKey(rand.Reader)
	if agentXKeyErr != nil {
		t.Fatal(agentXKeyErr)
	}
	agentYPub, agentYKey, agentYKeyErr := ed25519.GenerateKey(rand.Reader)
	if agentYKeyErr != nil {
		t.Fatal(agentYKeyErr)
	}
	agentXID := hex.EncodeToString(agentXPub)
	agentYID := hex.EncodeToString(agentYPub)
	operatorID := hex.EncodeToString(source.agentPub)
	const domain = "shared.notes"
	const secondDomain = "shared.private"

	insertCommitted(t, destination, "identity-memory", domain,
		"the connected peer's ordinary agents may read this exported sentinel")
	insertCommitted(t, destination, "second-memory", secondDomain,
		"legacy linked rows do not narrow the directional peer export")

	listener := startListener(t, destination)
	federate(t, destination, source, "https://unused.invalid", []string{"shared"}, 4, 0)
	federate(t, source, destination, listener.URL, []string{"shared"}, 4, 0)
	enableV23Pair(t, source, destination, []string{"shared"})

	// Hold the source-side REST preflight constant. X and Y are reviewed local
	// Admins and the source operator is current Root; all three have clearance
	// 4 and the same positive central-policy Read decision for the exact domain.
	enrollV23SourceReadAllAdmin(t, source, "agent-x", agentXPub, 2)
	enrollV23SourceReadAllAdmin(t, source, "agent-y", agentYPub, 4)
	if err := source.badger.RegisterDomain(domain, operatorID, "", 6); err != nil {
		t.Fatal(err)
	}
	for _, principal := range []struct {
		name string
		id   string
	}{
		{name: "linked agent X", id: agentXID},
		{name: "unlinked agent Y", id: agentYID},
		{name: "source peer operator", id: operatorID},
	} {
		decision, authErr := source.badger.AuthorizeAppV23LocalDomain(
			principal.id, domain, store.AppV23VerbRead, false,
		)
		if authErr != nil || !decision.Allowed || decision.ExplicitDeny {
			t.Fatalf("%s did not have identical source Read preflight: decision=%+v err=%v",
				principal.name, decision, authErr)
		}
		enrollment, enrollmentErr := source.badger.GetAppV23Enrollment(principal.id)
		if enrollmentErr != nil || enrollment == nil || enrollment.Clearance != 4 {
			t.Fatalf("%s source clearance: enrollment=%+v err=%v",
				principal.name, enrollment, enrollmentErr)
		}
	}

	// X also has a legacy linked-reader row scoped to one domain. It remains a
	// positive compatibility capability and does not narrow the new directional
	// peer export. Y has no row at all. Neither requires a mirrored source group.
	addV23TestGuest(t, destination, source, agentXID, domain, 4)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	available, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentXID, []string{domain},
	)
	if availabilityErr != nil || len(available) != 1 || available[0] != domain {
		t.Fatalf("linked agent availability = %v err=%v, want [%s]", available, availabilityErr, domain)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentXID, []string{domain, secondDomain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain, secondDomain}) {
		t.Fatalf("legacy X link unexpectedly narrowed the peer export: domains=%v err=%v", got, availabilityErr)
	}

	// Y is not mirrored into any destination-local group. As an active ordinary
	// source agent it nevertheless receives every destination-exported domain.
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentYID, []string{domain, secondDomain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain, secondDomain}) {
		t.Fatalf("ordinary Y did not inherit the peer export: domains=%v err=%v", got, availabilityErr)
	}
	yPlan := planV23QueryForAgent(t, source, destination, agentYID, secondDomain)
	yQuery := signV23QueryAs(t, agentYKey, yPlan, &QueryRequest{
		Mode: ModeText, Query: "legacy linked rows", DomainTag: secondDomain, TopK: 5,
	})
	yResponse, yQueryErr := source.mgr.QueryPeer(ctx, destination.chainID, yQuery)
	if yQueryErr != nil || len(yResponse.Results) != 1 || yResponse.Results[0].MemoryID != "second-memory" {
		t.Fatalf("default-export Y recall: response=%+v err=%v", yResponse, yQueryErr)
	}

	// Root/the peer operator is never an ordinary agent. The source must refuse
	// to attest it before discovery, planning, or query transport.
	if _, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, operatorID, []string{domain},
	); availabilityErr == nil || !strings.Contains(availabilityErr.Error(), "active ordinary source agent") {
		t.Fatalf("source peer operator availability denial = %v", availabilityErr)
	}
	operatorPlan, planErr := source.mgr.PlanRecall(
		ctx, []string{destination.chainID}, operatorID, domain,
	)
	if planErr != nil || len(operatorPlan.Destinations) != 0 ||
		!strings.Contains(operatorPlan.Errors[destination.chainID], "active ordinary source agent") {
		t.Fatalf("source peer operator plan denial: plan=%+v err=%v", operatorPlan, planErr)
	}
	// Even a directly authenticated peer request cannot omit the ordinary-agent
	// attestation and use the outer operator as a read credential.
	sourceAgreement, agreementErr := source.mgr.ActiveAgreement(destination.chainID)
	if agreementErr != nil {
		t.Fatal(agreementErr)
	}
	_, status, requestErr := source.mgr.doPeerRequest(ctx, sourceAgreement, http.MethodPost,
		"/fed/v1/query/plan", &QueryPlanRequest{
			AgentID: operatorID, DomainTag: domain, SourceAgentEligible: false,
		})
	if requestErr != nil || status != http.StatusForbidden {
		t.Fatalf("missing source ordinary-agent attestation: status=%d err=%v", status, requestErr)
	}
	_, status, requestErr = source.mgr.doPeerRequest(ctx, sourceAgreement, http.MethodPost,
		"/fed/v1/query/plan", &QueryPlanRequest{
			AgentID: agentYID, DomainTag: domain,
			SourceAuthorizationModel: "future-unknown-model",
			SourceAgentEligible:      true, SourceAgentMaxClassification: 4,
		})
	if requestErr != nil || status != http.StatusForbidden {
		t.Fatalf("unknown source authorization model: status=%d err=%v", status, requestErr)
	}
	// Mixed-version compatibility is fail-closed: an omitted model uses only the
	// legacy exact linked-reader capability. X has one; ordinary unlinked Y does
	// not inherit the new broad export unless the peer negotiated peer-export-v1.
	_, status, requestErr = source.mgr.doPeerRequest(ctx, sourceAgreement, http.MethodPost,
		"/fed/v1/query/plan", &QueryPlanRequest{AgentID: agentXID, DomainTag: domain})
	if requestErr != nil || status != http.StatusOK {
		t.Fatalf("legacy linked-reader compatibility: status=%d err=%v", status, requestErr)
	}
	_, status, requestErr = source.mgr.doPeerRequest(ctx, sourceAgreement, http.MethodPost,
		"/fed/v1/query/plan", &QueryPlanRequest{AgentID: agentYID, DomainTag: domain})
	if requestErr != nil || status != http.StatusForbidden {
		t.Fatalf("legacy unlinked identity did not fail closed: status=%d err=%v", status, requestErr)
	}

	linkedPlan := planV23QueryForAgent(t, source, destination, agentXID, domain)
	linkedQuery := signV23QueryAs(t, agentXKey, linkedPlan, &QueryRequest{
		Mode: ModeText, Query: "connected peer ordinary agents", DomainTag: domain, TopK: 5,
	})
	response, queryErr := source.mgr.QueryPeer(ctx, destination.chainID, linkedQuery)
	if queryErr != nil {
		t.Fatalf("exact linked X recall: %v", queryErr)
	}
	if len(response.Results) != 1 || response.Results[0].MemoryID != "identity-memory" {
		t.Fatalf("exact linked X result: %+v", response.Results)
	}

	// Pausing a legacy linked capability does not turn it into a negative ACL or
	// revoke the independent peer export. Source-side DomainAccess and the peer
	// policy are the explicit narrowing layers.
	guestRows, guestErr := destination.mem.(*store.SQLiteStore).ListFederatedGroupGuests(
		ctx, source.chainID, agentXID,
	)
	if guestErr != nil || len(guestRows) != 1 {
		t.Fatalf("load X override: rows=%+v err=%v", guestRows, guestErr)
	}
	paused := guestRows[0]
	paused.Revision++
	paused.State = store.FederatedGuestStatePaused
	if signErr := store.SignFederatedGroupGuest(&paused, destination.agentKey); signErr != nil {
		t.Fatal(signErr)
	}
	if putErr := destination.mem.(*store.SQLiteStore).PutFederatedGroupGuest(ctx, paused); putErr != nil {
		t.Fatal(putErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentXID, []string{domain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain}) {
		t.Fatalf("legacy X pause incorrectly revoked peer export: domains=%v err=%v", got, availabilityErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentYID, []string{domain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain}) {
		t.Fatalf("X pause incorrectly denied independent Y: domains=%v err=%v", got, availabilityErr)
	}

	// Pausing the peer policy itself revokes the export for every source agent;
	// resuming restores the saved directional policy without recreating groups.
	if _, pauseErr := destination.mgr.SetPeerRBACPaused(ctx, source.chainID, true); pauseErr != nil {
		t.Fatal(pauseErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentYID, []string{domain},
	); availabilityErr != nil || len(got) != 0 {
		t.Fatalf("paused peer policy disclosed to Y: domains=%v err=%v", got, availabilityErr)
	}
	if _, resumeErr := destination.mgr.SetPeerRBACPaused(ctx, source.chainID, false); resumeErr != nil {
		t.Fatal(resumeErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentYID, []string{domain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain}) {
		t.Fatalf("resumed peer export did not restore Y: domains=%v err=%v", got, availabilityErr)
	}
	policy, policyErr := destination.mgr.GetPeerRBACPolicy(ctx, source.chainID)
	if policyErr != nil || policy == nil {
		t.Fatalf("load destination peer policy: policy=%+v err=%v", policy, policyErr)
	}
	policy.Domains = nil
	if _, replaceErr := destination.mem.(*store.SQLiteStore).ReplaceBoundPeerRBACPolicy(ctx, *policy); replaceErr != nil {
		t.Fatal(replaceErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, agentYID, []string{domain},
	); availabilityErr != nil || len(got) != 0 {
		t.Fatalf("removed peer export still disclosed: domains=%v err=%v", got, availabilityErr)
	}

	// A linked-reader row is not local enrollment and carries no mutation or
	// governance fields. All three remote identities remain non-principals on
	// the destination, and the real authenticated write route stays a typed 501.
	guestType := reflect.TypeOf(store.FederatedGroupGuest{})
	for _, field := range []string{"Write", "Copy", "Modify", "Claim", "Govern"} {
		if _, present := guestType.FieldByName(field); present {
			t.Fatalf("federated guest schema unexpectedly grants %s", field)
		}
	}
	for _, id := range []string{agentXID, agentYID, operatorID} {
		enrollment, enrollmentErr := destination.badger.GetAppV23Enrollment(id)
		if enrollmentErr != nil || enrollment != nil {
			t.Fatalf("remote identity became a local destination principal: id=%s enrollment=%+v err=%v",
				id, enrollment, enrollmentErr)
		}
		for _, verb := range []store.AppV23DomainVerb{
			store.AppV23VerbWrite,
			store.AppV23VerbModify,
		} {
			decision, authErr := destination.badger.AuthorizeAppV23LocalDomain(
				id, domain, verb, false,
			)
			if authErr == nil && decision.Allowed {
				t.Fatalf("remote identity gained destination mutation: id=%s verb=%d decision=%+v",
					id, verb, decision)
			}
		}
		if _, writeErr := source.mgr.WritePeer(ctx, destination.chainID, &RemoteWriteRequest{
			Headers: RemoteWriteHeaders{AgentID: id},
		}); !errors.Is(writeErr, ErrRemoteWriteCapabilityUnavailable) {
			t.Fatalf("remote write preflight for %s = %v", id, writeErr)
		}
	}
	agreement, err := source.mgr.ActiveAgreement(destination.chainID)
	if err != nil {
		t.Fatal(err)
	}
	writeBody, writeStatus, err := source.mgr.doPeerRequest(
		ctx, agreement, http.MethodPost, "/fed/v1/write", map[string]any{"agent_id": agentXID},
	)
	if err != nil {
		t.Fatal(err)
	}
	const exactWriteDenial = `{"error":"federation write requires a consensus-bound ingress capability and is unavailable in the current protocol"}`
	if writeStatus != http.StatusNotImplemented ||
		strings.TrimSpace(string(writeBody)) != exactWriteDenial {
		t.Fatalf("authenticated remote write = status %d body %q",
			writeStatus, strings.TrimSpace(string(writeBody)))
	}
	for _, path := range []string{"/fed/v1/domain/claim", "/fed/v1/governance/propose"} {
		_, status, routeErr := source.mgr.doPeerRequest(
			ctx, agreement, http.MethodPost, path, map[string]any{"agent_id": agentXID},
		)
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		if status != http.StatusNotFound {
			t.Fatalf("federated mutation route %s unexpectedly exists: status=%d", path, status)
		}
	}
}
