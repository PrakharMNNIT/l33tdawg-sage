package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	badger "github.com/dgraph-io/badger/v4"
)

// ListAppV23AccessGroups returns the complete bounded consensus group
// inventory in canonical group-id order for operator projections and state
// validation. It never consults browser or SQL grouping state.
func (s *BadgerStore) ListAppV23AccessGroups() ([]AppV23AccessGroup, error) {
	groups := make([]AppV23AccessGroup, 0)
	prefix := []byte("appv23:group:")
	err := s.view(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if len(groups) == AppV23MaxGroups {
				return errors.New("app-v23 group count exceeds deterministic bound")
			}
			var group AppV23AccessGroup
			if err := it.Item().Value(func(value []byte) error {
				return json.Unmarshal(value, &group)
			}); err != nil {
				return err
			}
			if group.GroupID != string(it.Item().Key()[len(prefix):]) {
				return errors.New("app-v23 access group key/value invariant failed")
			}
			groups = append(groups, group)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].GroupID < groups[j].GroupID })
	return groups, nil
}

// ResolveAppV23OwningAncestor resolves the nearest effective owner while
// treating every static or consensus-marked shared candidate as an ownership
// inheritance barrier. Unlike ResolveOwningAncestor, this helper is app-v23
// only: it observes the state-backed shared_domain:<name> registry and stops
// rather than falling through to a less-specific owner.
func (s *BadgerStore) ResolveAppV23OwningAncestor(
	domain string,
) (owner, ownedDomain string, err error) {
	if domain == "" {
		return "", "", nil
	}
	segments := splitDomainSegments(domain)
	if len(segments) == 0 {
		return "", "", nil
	}
	if len(segments) > 16 {
		return "", "", ErrDomainPathTooDeep
	}
	err = s.view(func(txn *badger.Txn) error {
		for i := len(segments); i >= 1; i-- {
			candidate := strings.Join(segments[:i], ".")
			shared, sharedErr := appV23DomainIsSharedTxn(txn, candidate)
			if sharedErr != nil {
				return sharedErr
			}
			if shared {
				// A shared namespace has no effective owner. In particular,
				// never skip it and then inherit a broader ancestor owner.
				return nil
			}
			value, getErr := s.appV23ReadEffectiveValueTxn(txn, domainKey(candidate))
			switch {
			case errors.Is(getErr, badger.ErrKeyNotFound):
				continue
			case getErr != nil:
				return getErr
			}
			candidateOwner, _, decodeErr := decodeString(value, 0)
			if decodeErr != nil {
				return decodeErr
			}
			if candidateOwner == "" {
				continue
			}
			owner, ownedDomain = candidateOwner, candidate
			return nil
		}
		return nil
	})
	return owner, ownedDomain, err
}

// FederatedGuestGroupAllowsDomain resolves the live, consensus-authoritative
// local half of a federated linked-reader relationship. A linked reader may
// see a domain only while its owning agent is actively enrolled in the exact
// referenced Access Group. Shared/ownerless domains and stale membership never
// become visible through this relation.
func (s *BadgerStore) FederatedGuestGroupAllowsDomain(
	ctx context.Context,
	groupID, domain string,
) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	group, err := s.GetAppV23AccessGroup(groupID)
	if err != nil || group == nil {
		return false, err
	}
	owner, _, err := s.ResolveAppV23OwningAncestor(domain)
	if err != nil || owner == "" {
		return false, err
	}
	enrollment, err := s.GetAppV23Enrollment(owner)
	if err != nil || enrollment == nil || !enrollment.Active {
		return false, err
	}
	index := sort.SearchStrings(group.Members, owner)
	return index < len(group.Members) && group.Members[index] == owner, nil
}
