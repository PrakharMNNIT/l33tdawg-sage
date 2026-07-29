package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/l33tdawg/sage/internal/store"
)

// verifyAppV23VendoredAgentReadiness is deliberately read-only. Mynah has no
// released legacy population: an explicitly configured first-party companion
// must come from the dual-signed direct-v23 genesis path and already have its
// exact committed enrollment. A legacy/mismatched chain fails startup instead
// of being silently mutated into a lookalike policy state.
func verifyAppV23VendoredAgentReadiness(
	bootstrap *VendoredAgentBootstrapConfig,
	resolveLocalKey func(string) (ed25519.PrivateKey, bool),
	badgerStore *store.BadgerStore,
) error {
	if bootstrap == nil || resolveLocalKey == nil || badgerStore == nil {
		return errors.New("vendored readiness verifier is incomplete")
	}
	targetKey, ok := parseKeyFile(bootstrap.AgentKeyFile)
	if !ok || len(targetKey) != ed25519.PrivateKeySize {
		return errors.New("configured first-party agent key is unavailable")
	}
	targetID := appV23AgentIDForKey(targetKey)
	if targetID == "" {
		return errors.New("configured first-party agent key is invalid")
	}
	activation, err := badgerStore.GetAppV23GenesisActivation()
	if err != nil {
		return fmt.Errorf("read direct app-v23 genesis activation: %w", err)
	}
	if activation == nil {
		return errors.New(
			"configured first-party agent requires a fresh dual-signed app-v23 genesis; automatic legacy repair is not supported",
		)
	}
	if lineageErr := badgerStore.ValidateAppV23GenesisLineage(); lineageErr != nil {
		return fmt.Errorf("invalid direct app-v23 genesis lineage: %w", lineageErr)
	}
	if stateErr := badgerStore.ValidateAppV23State(); stateErr != nil {
		return fmt.Errorf("invalid direct app-v23 policy state: %w", stateErr)
	}
	root, err := badgerStore.GetAppV23Root()
	if err != nil || root == nil {
		return errors.New("direct app-v23 genesis Root state is unavailable")
	}
	if root.Scope != activation.Scope ||
		root.BootstrapDigest != activation.BootstrapDigest {
		return errors.New("direct app-v23 genesis marker does not match Root state")
	}
	if activation.RootID != root.PrincipalID {
		return errors.New("current Root principal does not match immutable direct app-v23 genesis provenance")
	}
	if targetID != activation.AgentID ||
		bootstrap.HomeDomain != activation.HomeDomain ||
		bootstrap.Clearance != activation.Clearance ||
		activation.Profile != store.AppV23ProfileCompanion ||
		activation.Capabilities != 15 {
		return errors.New("configured first-party agent does not match immutable direct app-v23 genesis provenance")
	}
	currentRootKey, ok := resolveLocalKey(root.CredentialID)
	if !ok || len(currentRootKey) != ed25519.PrivateKeySize ||
		appV23AgentIDForKey(currentRootKey) != root.CredentialID {
		return errors.New("current committed CEREBRUM Root credential is not available on this node")
	}
	rootGeneration, found, err :=
		badgerStore.GetAppV23RootCredentialGeneration(root.CredentialID)
	if err != nil || !found || rootGeneration != root.Generation {
		return errors.New("current committed CEREBRUM Root credential lacks exact generation provenance")
	}

	registered, err := badgerStore.GetRegisteredAgent(targetID)
	if err != nil || registered == nil {
		return errors.New("configured first-party agent is not registered")
	}
	decision, err := badgerStore.AuthorizeAppV23LocalDomain(
		targetID,
		activation.HomeDomain,
		store.AppV23VerbWrite,
		false,
	)
	if err != nil {
		return fmt.Errorf("evaluate configured first-party write readiness: %w", err)
	}
	if decision.Allowed {
		return nil
	}
	if !decision.ExplicitDeny {
		hasGrant, grantErr := badgerStore.HasAppV23AccessOrAncestor(
			activation.HomeDomain,
			targetID,
			2,
			time.Now(),
			false,
		)
		if grantErr != nil {
			return fmt.Errorf("evaluate configured first-party write grant: %w", grantErr)
		}
		if hasGrant {
			return nil
		}
	}
	return errors.New("configured first-party agent cannot write its immutable direct app-v23 home domain")
}

func appV23AgentIDForKey(key ed25519.PrivateKey) string {
	if len(key) != ed25519.PrivateKeySize {
		return ""
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return hex.EncodeToString(public)
}
