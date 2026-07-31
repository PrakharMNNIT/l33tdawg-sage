package appv23disclosure

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/l33tdawg/sage/internal/store"
)

// Record is the consensus-relevant subset of a memory needed for a post-v23
// content-disclosure decision. Classification must come from the route's
// authoritative classification projection.
type Record struct {
	SubmittingAgent string
	Domain          string
	Classification  uint8
}

// Decision is deliberately small so REST and dashboard task surfaces can use
// one policy without revealing why a denied record exists.
type Decision struct {
	Allowed bool
}

// Evaluate applies app-v23's complete local record-disclosure policy:
// current enrollment and clearance, immutable migration visible_agents and
// read compatibility, then current profile/group/grant scope. Authorship and
// task assignment are provenance, never continuing read authority.
func Evaluate(
	badgerStore *store.BadgerStore,
	credentialID string,
	record Record,
	at time.Time,
) (Decision, error) {
	if badgerStore == nil || credentialID == "" || record.Domain == "" {
		return Decision{}, errors.New("app-v23 record authorization state is unavailable")
	}

	policyID, err := policyPrincipal(badgerStore, credentialID)
	if err != nil {
		return Decision{}, err
	}
	enrollment, err := badgerStore.GetAppV23Enrollment(policyID)
	if err != nil {
		return Decision{}, err
	}
	if enrollment == nil || !enrollment.Active {
		return Decision{}, nil
	}
	recoveredDirect, recoveredErr := badgerStore.AuthorizeAppV25RecoveredDirectRead(
		credentialID, record.Domain,
	)
	if recoveredErr != nil {
		return Decision{}, recoveredErr
	}
	if recoveredDirect {
		return Decision{Allowed: record.Classification <= enrollment.Clearance}, nil
	}

	visibleAgents, restricted, err := badgerStore.AppV23LegacyVisibleAgents(policyID)
	if err != nil {
		return Decision{}, err
	}
	if restricted && record.SubmittingAgent != credentialID {
		switch visibleAgents {
		case "*":
			// The immutable baseline already allowed every author.
		case "":
			return Decision{}, nil
		default:
			var allowedAuthors []string
			if decodeErr := json.Unmarshal([]byte(visibleAgents), &allowedAuthors); decodeErr != nil {
				return Decision{}, errors.New("app-v23 legacy visibility state is invalid")
			}
			visible := false
			for _, authorID := range allowedAuthors {
				if authorID == record.SubmittingAgent {
					visible = true
					break
				}
			}
			if !visible {
				return Decision{}, nil
			}
		}
	}

	legacy, err := badgerStore.AppV23LegacyReadCompatibility(
		policyID, record.Domain, record.Classification, at,
	)
	if err != nil {
		return Decision{}, err
	}
	if record.Classification > enrollment.Clearance {
		// Migration-only org/federation clearance may preserve exactly the H-1
		// local read envelope even when the new enrollment slot is lower.
		return Decision{Allowed: legacy.Allowed}, nil
	}

	shared, err := badgerStore.IsAppV23SharedDomain(record.Domain)
	if err != nil {
		return Decision{}, err
	}
	current, err := badgerStore.AuthorizeAppV23LocalDomain(
		credentialID, record.Domain, store.AppV23VerbRead, shared,
	)
	if err != nil {
		return Decision{}, err
	}
	if current.ExplicitDeny {
		return Decision{}, nil
	}
	policyAllowed := current.Allowed
	grantAllowed := false
	if !policyAllowed {
		grantAllowed, err = badgerStore.HasAppV23AccessOrAncestor(
			record.Domain, credentialID, 1, at, shared,
		)
		if err != nil {
			return Decision{}, err
		}
	}
	if legacy.ExplicitDomainRestriction && !legacy.Allowed {
		// A frozen explicit allowlist continues to restrict ordinary grants. It
		// cannot, however, make a directly governed recovered-domain owner,
		// continuity writer/group member, Admin, or Root write-only.
		return Decision{}, nil
	}
	return Decision{Allowed: policyAllowed || grantAllowed || legacy.Allowed}, nil
}

func policyPrincipal(
	badgerStore *store.BadgerStore,
	credentialID string,
) (string, error) {
	root, err := badgerStore.GetAppV23Root()
	if err != nil {
		return "", err
	}
	if root != nil && credentialID == root.CredentialID {
		return root.PrincipalID, nil
	}
	if root != nil {
		wasRoot, err := badgerStore.IsAppV23RootCredential(credentialID)
		if err != nil {
			return "", err
		}
		if wasRoot {
			return "", errors.New("authenticated credential is a retired Root credential")
		}
	}
	return credentialID, nil
}
