package store

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/l33tdawg/sage/internal/memory"
)

// ErrMemoryProjectionUnpublished marks an off-chain row that does not match
// the canonical Badger snapshot currently published to readers. Callers must
// fail closed: the row may be from the SQL-before-Badger crash window and will
// become visible only after consensus replay completes the matching Commit.
var ErrMemoryProjectionUnpublished = errors.New("memory projection is not canonically published")

// ValidateMemoryProjection verifies that a serving-layer record is the exact
// projection of one committed on-chain memory snapshot. It also returns the
// classification from that same Badger read transaction so disclosure policy
// cannot combine fields from opposite sides of a concurrent Commit.
func (s *BadgerStore) ValidateMemoryProjection(
	record *memory.MemoryRecord,
) (*MemoryDisclosureState, error) {
	if s == nil || record == nil || record.MemoryID == "" {
		return nil, fmt.Errorf("%w: missing store or record identity", ErrMemoryProjectionUnpublished)
	}
	state, err := s.GetMemoryDisclosureState(record.MemoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMemoryProjectionUnpublished, err)
	}
	if len(record.ContentHash) == 0 || !bytes.Equal(record.ContentHash, state.ContentHash) {
		return nil, fmt.Errorf("%w: content hash mismatch for %s",
			ErrMemoryProjectionUnpublished, record.MemoryID)
	}
	if record.Content == "" {
		if !state.CoCommitRecorded {
			return nil, fmt.Errorf("%w: empty content is not a canonical hash-only co-commit for %s",
				ErrMemoryProjectionUnpublished, record.MemoryID)
		}
	} else if computed := memory.ComputeContentHash(record.Content); !bytes.Equal(computed, state.ContentHash) {
		return nil, fmt.Errorf("%w: content does not match canonical hash for %s",
			ErrMemoryProjectionUnpublished, record.MemoryID)
	}
	if string(record.Status) != state.Status {
		return nil, fmt.Errorf("%w: status mismatch for %s",
			ErrMemoryProjectionUnpublished, record.MemoryID)
	}
	if state.DomainRecorded && record.DomainTag != state.Domain {
		return nil, fmt.Errorf("%w: domain mismatch for %s",
			ErrMemoryProjectionUnpublished, record.MemoryID)
	}
	if state.AuthorRecorded && record.SubmittingAgent != state.Author {
		return nil, fmt.Errorf("%w: author mismatch for %s",
			ErrMemoryProjectionUnpublished, record.MemoryID)
	}
	return state, nil
}
