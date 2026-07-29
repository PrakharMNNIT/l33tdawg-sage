package statesync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/taskidempotency"
)

func stateSyncFixture(t *testing.T) (Metadata, []byte, []byte, [][]byte, []byte) {
	t.Helper()
	appHash := sha256.Sum256([]byte("trusted app hash"))
	payload := bytes.Repeat([]byte("canonical-badger-backup"), 6_100)
	chunks := make([][]byte, 0, 3)
	for offset := 0; offset < len(payload); offset += int(MinChunkSize) {
		end := offset + int(MinChunkSize)
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, append([]byte(nil), payload[offset:end]...))
	}
	metadata, encoded, snapshotHash, err := BuildMetadata(42, appHash[:], MinChunkSize, chunks)
	require.NoError(t, err)
	return metadata, encoded, snapshotHash, chunks, payload
}

func TestCanonicalStatePromotesAppV23StageOnlyAfterActivation(t *testing.T) {
	source, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, source.CloseBadger()) })
	var memberID string
	for i := 0; i < 513; i++ {
		id := fmt.Sprintf("%064x", i+1)
		role := store.AppV23RoleMember
		if i == 0 {
			role = store.AppV23RoleAdmin
		}
		if i == 1 {
			memberID = id
		}
		require.NoError(t, source.RegisterAgentWithCapabilities(
			id, fmt.Sprintf("legacy-%d", i), role, "", "", "",
			int64(i+1), 0,
		))
	}
	require.NoError(t, source.PrepareAppV23Migration("canonical-stage", 100))

	stagePrefix := []byte{0xff, 's', 'a', 'g', 'e', ':', 'a', 'p', 'p', 'v', '2', '3', ':', 's', 't', 'a', 'g', 'e', ':'}
	var preActivation bytes.Buffer
	require.NoError(t, WriteCanonicalState(context.Background(), source.DB(), &preActivation))
	require.False(t, bytes.Contains(preActivation.Bytes(), stagePrefix),
		"unpromoted preparation rows are local and must not enter state sync")

	require.NoError(t, source.EnsureAppV23Root("canonical-stage", 100))
	idempotencyKey := "state-sync-task-v1"
	memoryID, err := taskidempotency.MemoryID(memberID, idempotencyKey)
	require.NoError(t, err)
	keyDigest, err := taskidempotency.BindingKeyDigest(memberID, idempotencyKey)
	require.NoError(t, err)
	contentHash := sha256.Sum256([]byte("[TASK] survive state sync"))
	require.NoError(t, source.SetMemoryHash(memoryID, contentHash[:], "proposed"))
	require.NoError(t, source.SetMemoryDomain(memoryID, "legacy-1"))
	require.NoError(t, source.SetMemoryClassification(memoryID, 0))
	require.NoError(t, source.SetMemoryAuthorPrincipal(memoryID, memberID))
	binding := &store.AppV23TaskIdempotencyBinding{
		Version: 1, PrincipalID: memberID,
		BindingKeyDigest: taskidempotency.Hex(keyDigest),
		PayloadDigest:    strings.Repeat("ab", 32),
		MemoryID:         memoryID, AssigneeID: memberID,
		CommittedHeight: 101, TxHash: strings.Repeat("CD", 32),
	}
	require.NoError(t, source.SetAppV23TaskIdempotencyBinding(
		memberID, idempotencyKey, binding,
	))
	require.NoError(t, source.ValidateAppV23State())
	sourceHash, err := source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	var activated bytes.Buffer
	require.NoError(t, WriteCanonicalState(context.Background(), source.DB(), &activated))
	require.True(t, bytes.Contains(activated.Bytes(), stagePrefix))

	restorePath := filepath.Join(t.TempDir(), "restored")
	opts := badger.DefaultOptions(restorePath).WithLogger(nil)
	raw, err := badger.Open(opts)
	require.NoError(t, err)
	require.NoError(t, RestoreCanonicalState(
		context.Background(), bytes.NewReader(activated.Bytes()), raw,
	))
	require.NoError(t, raw.Close())
	restored, err := store.NewBadgerStore(restorePath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.CloseBadger()) })
	require.NoError(t, restored.ValidateAppV23State())
	restoredBinding, err := restored.GetAppV23TaskIdempotencyBinding(
		memberID, idempotencyKey,
	)
	require.NoError(t, err)
	require.Equal(t, binding, restoredBinding,
		"canonical state sync must preserve the authoritative retry receipt")
	restoredHash, err := restored.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, sourceHash, restoredHash)
	enrollment, err := restored.GetAppV23Enrollment(memberID)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	require.True(t, enrollment.Active)
}

func TestMetadataCanonicalRoundTripAndTrustedOffer(t *testing.T) {
	metadata, encoded, snapshotHash, _, _ := stateSyncFixture(t)
	decoded, err := DecodeMetadata(encoded)
	require.NoError(t, err)
	assert.Equal(t, metadata, decoded)
	reencoded, err := EncodeMetadata(decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)

	offered, err := ValidateOffer(Format, metadata.Height, uint32(len(metadata.ChunkHashes)), snapshotHash, encoded, metadata.AppHash)
	require.NoError(t, err)
	assert.Equal(t, metadata, offered)

	_, err = ValidateOffer(Format+1, metadata.Height, uint32(len(metadata.ChunkHashes)), snapshotHash, encoded, metadata.AppHash)
	require.ErrorContains(t, err, "unsupported")
	wrongHash := sha256.Sum256([]byte("wrong trusted hash"))
	_, err = ValidateOffer(Format, metadata.Height, uint32(len(metadata.ChunkHashes)), snapshotHash, encoded, wrongHash[:])
	require.ErrorContains(t, err, "trusted AppHash")
	_, err = ValidateOffer(Format, metadata.Height, uint32(len(metadata.ChunkHashes)), wrongHash[:], encoded, metadata.AppHash)
	require.ErrorContains(t, err, "snapshot hash")
}

func TestMetadataRejectsLocalRollbackManifestAndMalformedInputs(t *testing.T) {
	_, err := DecodeMetadata([]byte(`{"height":42,"chunks":[{"name":"config.tar.zst"}]}`))
	require.Error(t, err, "the private local snapshot manifest is never a network format")

	metadata, encoded, _, _, _ := stateSyncFixture(t)
	_, err = DecodeMetadata(append(encoded, 0))
	require.ErrorContains(t, err, "canonical length")
	badVersion := append([]byte(nil), encoded...)
	badVersion[len(metadataMagic)]++
	_, err = DecodeMetadata(badVersion)
	require.ErrorContains(t, err, "unsupported")
	badCount := append([]byte(nil), encoded...)
	countOffset := 12 + 1 + 8 + sha256.Size + 8 + 4
	for i := 0; i < 4; i++ {
		badCount[countOffset+i] = 0xff
	}
	_, err = DecodeMetadata(badCount)
	require.ErrorContains(t, err, "chunk count")
	metadata.BackupSize = 0
	_, err = EncodeMetadata(metadata)
	require.ErrorContains(t, err, "backup size")
}

func TestAssemblerOutOfOrderDuplicateCorruptionAndCompleteHash(t *testing.T) {
	metadata, _, _, chunks, payload := stateSyncFixture(t)
	staging := filepath.Join(t.TempDir(), "assembly")
	assembler, err := NewAssembler(staging, metadata)
	require.NoError(t, err)
	assert.Equal(t, []uint32{0, 1, 2}, assembler.Missing())

	require.NoError(t, assembler.AddChunk(2, chunks[2]))
	require.NoError(t, assembler.AddChunk(0, chunks[0]))
	require.NoError(t, assembler.AddChunk(0, chunks[0]), "exact chunk redelivery is idempotent")
	corrupt := append([]byte(nil), chunks[1]...)
	corrupt[0] ^= 0xff
	require.ErrorContains(t, assembler.AddChunk(1, corrupt), "hash mismatch")
	assert.Equal(t, []uint32{1}, assembler.Missing())
	require.NoError(t, assembler.AddChunk(1, chunks[1]))
	assert.Empty(t, assembler.Missing())

	output := filepath.Join(t.TempDir(), "badger.backup")
	require.NoError(t, assembler.Assemble(output))
	got, err := os.ReadFile(output) //nolint:gosec // test-owned path
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	require.ErrorContains(t, assembler.Assemble(output), "already exists")
}

func TestAssemblerRejectsIncompleteWrongSizeAndExistingStage(t *testing.T) {
	metadata, _, _, chunks, _ := stateSyncFixture(t)
	parent := t.TempDir()
	staging := filepath.Join(parent, "assembly")
	assembler, err := NewAssembler(staging, metadata)
	require.NoError(t, err)
	_, err = NewAssembler(staging, metadata)
	require.Error(t, err, "existing staging state is never silently reused")
	require.ErrorContains(t, assembler.AddChunk(0, chunks[0][:len(chunks[0])-1]), "size")
	require.ErrorContains(t, assembler.AddChunk(uint32(len(chunks)), chunks[0]), "out of range")
	require.ErrorContains(t, assembler.Assemble(filepath.Join(parent, "out")), "incomplete")
}

func TestAssemblerContextCancellationLeavesNoPublishedImage(t *testing.T) {
	metadata, _, _, chunks, _ := stateSyncFixture(t)
	assembler, err := NewAssembler(filepath.Join(t.TempDir(), "assembly"), metadata)
	require.NoError(t, err)
	for index, chunk := range chunks {
		require.NoError(t, assembler.AddChunk(uint32(index), chunk)) // #nosec G115 -- bounded fixture
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output := filepath.Join(t.TempDir(), "canonical.state")
	err = assembler.AssembleContext(ctx, output)
	require.ErrorIs(t, err, context.Canceled)
	assert.NoFileExists(t, output)
}

func TestConsensusOnlyFormatRoundTripsCanonicalBadgerStateAndAppHash(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "source-badger")
	source, err := store.NewBadgerStore(sourcePath)
	require.NoError(t, err)
	require.NoError(t, source.SetState("scope:fixture", []byte("canonical scope state")))
	require.NoError(t, source.SetState("scope-content:fixture", []byte("selected content only")))
	appHash, err := source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	var backup bytes.Buffer
	require.NoError(t, WriteCanonicalState(context.Background(), source.DB(), &backup))
	require.NoError(t, source.CloseBadger())

	payload := backup.Bytes()
	chunks := make([][]byte, 0, (len(payload)+int(MinChunkSize)-1)/int(MinChunkSize))
	for offset := 0; offset < len(payload); offset += int(MinChunkSize) {
		end := offset + int(MinChunkSize)
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, append([]byte(nil), payload[offset:end]...))
	}
	metadata, encoded, snapshotHash, err := BuildMetadata(77, appHash, MinChunkSize, chunks)
	require.NoError(t, err)
	_, err = ValidateOffer(Format, 77, uint32(len(chunks)), snapshotHash, encoded, appHash)
	require.NoError(t, err)

	assembler, err := NewAssembler(filepath.Join(t.TempDir(), "stage"), metadata)
	require.NoError(t, err)
	for i := len(chunks) - 1; i >= 0; i-- {
		require.NoError(t, assembler.AddChunk(uint32(i), chunks[i]))
	}
	assembledPath := filepath.Join(t.TempDir(), "badger.backup")
	require.NoError(t, assembler.Assemble(assembledPath))

	restoredPath := filepath.Join(t.TempDir(), "restored-badger")
	db, err := badger.Open(badger.DefaultOptions(restoredPath).WithLogger(nil))
	require.NoError(t, err)
	backupFile, err := os.Open(assembledPath) //nolint:gosec // test-owned path
	require.NoError(t, err)
	require.NoError(t, RestoreCanonicalState(context.Background(), backupFile, db))
	require.NoError(t, backupFile.Close())
	require.NoError(t, db.Close())
	restored, err := store.NewBadgerStore(restoredPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.CloseBadger() })
	restoredHash, err := restored.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	assert.Equal(t, appHash, restoredHash)
}

func FuzzDecodeMetadata(f *testing.F) {
	appHash := sha256.Sum256([]byte("seed"))
	chunk := bytes.Repeat([]byte{0x42}, int(MinChunkSize))
	_, encoded, _, err := BuildMetadata(1, appHash[:], MinChunkSize, [][]byte{chunk})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"height":1,"chunks":["private-local-bundle"]}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		metadata, err := DecodeMetadata(input)
		if err != nil {
			return
		}
		reencoded, err := EncodeMetadata(metadata)
		require.NoError(t, err)
		require.Equal(t, input, reencoded)
	})
}
