package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTree materializes a small file tree for archive round-trips.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

func TestBackupArchiveRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"config.yaml":         "data_dir: data\n",
		"agents/a/agent.key":  "SEED-A",
		"data/badger/000.sst": "badger-bytes",
		"data/sage.db":        "sqlite-bytes",
	})
	// A prior archive under backups/ must not be swept into the new one.
	writeTree(t, src, map[string]string{"backups/old-full.tar.gz": "stale"})

	archive := filepath.Join(t.TempDir(), "out.tar.gz")
	manifest := backupManifest{
		Kind:          backupKindFull,
		CreatedAt:     time.Now().UTC(),
		BinaryVersion: "test",
		ForkVersion:   ConsensusForkVersion,
		Roots:         []string{src},
	}
	if _, _, err := writeBackupArchive(archive, []string{src}, manifest); err != nil {
		t.Fatalf("writeBackupArchive: %v", err)
	}

	got, err := readArchiveManifest(archive)
	if err != nil {
		t.Fatalf("readArchiveManifest: %v", err)
	}
	if got.Kind != backupKindFull || got.ForkVersion != ConsensusForkVersion {
		t.Fatalf("manifest round-trip mismatch: %+v", got)
	}

	dest := filepath.Join(t.TempDir(), "restored")
	if err := extractBackupArchive(archive, []string{dest}); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}

	for rel, want := range map[string]string{
		"config.yaml":         "data_dir: data\n",
		"agents/a/agent.key":  "SEED-A",
		"data/badger/000.sst": "badger-bytes",
		"data/sage.db":        "sqlite-bytes",
	} {
		b, readErr := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if readErr != nil {
			t.Fatalf("restored %s missing: %v", rel, readErr)
		}
		if string(b) != want {
			t.Fatalf("restored %s = %q, want %q", rel, b, want)
		}
	}

	// The backups directory is deliberately excluded — archiving prior archives
	// balloons the output and serves no recovery purpose.
	if _, statErr := os.Stat(filepath.Join(dest, "backups", "old-full.tar.gz")); statErr == nil {
		t.Fatal("backups/ was archived; it must be skipped")
	}
}

// Two roots (SAGE_HOME plus an out-of-tree data_dir) must land back in their
// own targets, not be merged.
func TestBackupArchiveSeparatesMultipleRoots(t *testing.T) {
	homeSrc := t.TempDir()
	dataSrc := t.TempDir()
	writeTree(t, homeSrc, map[string]string{"config.yaml": "home"})
	writeTree(t, dataSrc, map[string]string{"badger/000.sst": "data"})

	archive := filepath.Join(t.TempDir(), "multi.tar.gz")
	if _, _, err := writeBackupArchive(archive, []string{homeSrc, dataSrc}, backupManifest{
		Kind: backupKindFull, ForkVersion: ConsensusForkVersion, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("writeBackupArchive: %v", err)
	}

	outHome := filepath.Join(t.TempDir(), "home")
	outData := filepath.Join(t.TempDir(), "data")
	if err := extractBackupArchive(archive, []string{outHome, outData}); err != nil {
		t.Fatalf("extractBackupArchive: %v", err)
	}

	if b, err := os.ReadFile(filepath.Join(outHome, "config.yaml")); err != nil || string(b) != "home" {
		t.Fatalf("home root not restored: %v %q", err, b)
	}
	if b, err := os.ReadFile(filepath.Join(outData, "badger", "000.sst")); err != nil || string(b) != "data" {
		t.Fatalf("data root not restored: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(outHome, "badger")); err == nil {
		t.Fatal("data root leaked into the home target")
	}
}

// A crafted archive must never write outside its restore root.
func TestExtractBackupArchiveRejectsPathTraversal(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	payload := []byte("pwned")
	if err := tw.WriteHeader(&tar.Header{
		Name: "root0/../../escaped.txt", Mode: 0600,
		Size: int64(len(payload)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	dest := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(dest, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err = extractBackupArchive(archive, []string{dest})
	if err == nil {
		t.Fatal("path-traversal entry was accepted")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("unexpected error %v, want an escape refusal", err)
	}
}

// Liveness is decided by SAGE's own instance lock rather than a Badger probe:
// Badger refuses read-only opens outright on Windows, which would make backup
// and restore permanent brick walls there. Assert the lock actually gates.
func TestRequireStoppedNodeRefusesWhileInstanceLockHeld(t *testing.T) {
	home := t.TempDir()
	lock, err := acquireInstanceLock(home)
	if err != nil {
		t.Fatalf("acquire instance lock: %v", err)
	}
	defer func() { _ = lock.Close() }()

	if err := requireStoppedNode(home); err == nil {
		t.Fatal("requireStoppedNode reported a stopped node while the instance lock was held")
	}
}

// With no node running the probe must succeed and must not leave the lock held,
// or a second call (and the real node) would be locked out.
func TestRequireStoppedNodeAllowsStoppedNodeRepeatedly(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := requireStoppedNode(home); err != nil {
			t.Fatalf("call %d: stopped node refused: %v", i, err)
		}
	}
	lock, err := acquireInstanceLock(home)
	if err != nil {
		t.Fatalf("instance lock still held after probe: %v", err)
	}
	_ = lock.Close()
}

func TestBackupRootsDetectsNestedDataDir(t *testing.T) {
	home := t.TempDir()
	nestedData := filepath.Join(home, "data")
	if err := os.MkdirAll(nestedData, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	roots, nested, err := backupRoots(home, nestedData)
	if err != nil {
		t.Fatalf("backupRoots: %v", err)
	}
	if !nested {
		t.Fatal("data dir under SAGE home was not detected as nested")
	}
	if len(roots) != 1 {
		t.Fatalf("roots = %v, want just the home tree", roots)
	}
}

func TestBackupRootsCapturesExternalDataDir(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()

	roots, nested, err := backupRoots(home, external)
	if err != nil {
		t.Fatalf("backupRoots: %v", err)
	}
	if nested {
		t.Fatal("an out-of-tree data dir was reported as nested")
	}
	if len(roots) != 2 {
		t.Fatalf("roots = %v, want home and data trees", roots)
	}
}

// A sibling directory sharing a prefix with SAGE_HOME is not inside it. Without
// a separator-aware check, "/x/.sage-old" would be treated as nested under
// "/x/.sage" and silently dropped from the backup.
func TestBackupRootsPrefixSiblingIsNotNested(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, ".sage")
	sibling := filepath.Join(base, ".sage-old")
	for _, d := range []string{home, sibling} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	roots, nested, err := backupRoots(home, sibling)
	if err != nil {
		t.Fatalf("backupRoots: %v", err)
	}
	if nested {
		t.Fatal("prefix-sharing sibling was misdetected as nested")
	}
	if len(roots) != 2 {
		t.Fatalf("roots = %v, want both trees", roots)
	}
}

func TestSplitRootPrefix(t *testing.T) {
	cases := []struct {
		name    string
		wantIdx int
		wantRel string
		wantOK  bool
	}{
		{"root0/config.yaml", 0, "config.yaml", true},
		{"root2/a/b/c.txt", 2, "a/b/c.txt", true},
		{"root1/", 1, ".", true},
		{"sage-backup-manifest.json", 0, "", false},
		{"notaroot/x", 0, "", false},
	}
	for _, tc := range cases {
		idx, rel, ok := splitRootPrefix(tc.name)
		if ok != tc.wantOK {
			t.Fatalf("%q: ok = %v, want %v", tc.name, ok, tc.wantOK)
		}
		if !ok {
			continue
		}
		if idx != tc.wantIdx || rel != tc.wantRel {
			t.Fatalf("%q: got (%d,%q), want (%d,%q)", tc.name, idx, rel, tc.wantIdx, tc.wantRel)
		}
	}
}

func TestReadArchiveManifestRejectsNonBackup(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "plain.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0600, Size: 0, Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("header: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	if _, err := readArchiveManifest(archive); err == nil {
		t.Fatal("archive without a manifest was accepted as a SAGE backup")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:             "512 B",
		2048:            "2.0 KB",
		5 * 1024 * 1024: "5.0 MB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Fatalf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

// --full must be honoured wherever it appears, and the =-form must be parsed
// rather than passed through. Both failure modes silently downgrade to the
// SQLite-only projection copy while the operator believes they hold a complete
// pre-upgrade backup.
func TestExtractFullBackupFlagIsOrderIndependent(t *testing.T) {
	cases := []struct {
		args     []string
		wantFull bool
		wantRest []string
	}{
		{[]string{"--full"}, true, []string{}},
		{[]string{"--full", "--out", "x"}, true, []string{"--out", "x"}},
		{[]string{"--out", "x", "--full"}, true, []string{"--out", "x"}},
		{[]string{"--full=true"}, true, []string{}},
		{[]string{"--full=false"}, false, []string{}},
		{[]string{"--out", "x"}, false, []string{"--out", "x"}},
		{[]string{}, false, []string{}},
	}
	for _, tc := range cases {
		rest, full, err := extractFullBackupFlag(tc.args)
		if err != nil {
			t.Fatalf("%v: unexpected error %v", tc.args, err)
		}
		if full != tc.wantFull {
			t.Fatalf("%v: full = %v, want %v", tc.args, full, tc.wantFull)
		}
		if strings.Join(rest, " ") != strings.Join(tc.wantRest, " ") {
			t.Fatalf("%v: rest = %v, want %v", tc.args, rest, tc.wantRest)
		}
	}
}

func TestExtractFullBackupFlagRejectsGarbageBoolean(t *testing.T) {
	if _, _, err := extractFullBackupFlag([]string{"--full=yes-please"}); err == nil {
		t.Fatal("garbage --full value was accepted")
	}
}

// A symlinked data_dir must be followed, not archived as a one-line link entry.
// Otherwise the archive contains zero consensus state and still reports success.
func TestBackupRootsFollowsSymlinkedDataDir(t *testing.T) {
	home := t.TempDir()
	real := t.TempDir()
	link := filepath.Join(home, "data")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	roots, nested, err := backupRoots(home, link)
	if err != nil {
		t.Fatalf("backupRoots: %v", err)
	}
	if nested {
		t.Fatal("a data_dir symlinked outside SAGE home was reported as nested")
	}
	if len(roots) != 2 {
		t.Fatalf("roots = %v, want the home tree and the resolved data tree", roots)
	}
}

// A symlink entry whose target escapes the root turns every later file entry
// into an arbitrary write. Reject the symlink itself.
func TestExtractBackupArchiveRejectsEscapingSymlink(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "hatch.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "root0/hatch", Linkname: "../../outside", Typeflag: tar.TypeSymlink, Mode: 0777,
	}); err != nil {
		t.Fatalf("header: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	dest := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(dest, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err = extractBackupArchive(archive, []string{dest})
	if err == nil {
		t.Fatal("escaping symlink entry was accepted")
	}
	if !strings.Contains(err.Error(), "outside the restore root") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestExtractBackupArchiveRejectsAbsoluteSymlink(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "abs.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "root0/hatch", Linkname: "/etc", Typeflag: tar.TypeSymlink, Mode: 0777,
	}); err != nil {
		t.Fatalf("header: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	dest := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(dest, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := extractBackupArchive(archive, []string{dest}); err == nil {
		t.Fatal("absolute symlink entry was accepted")
	}
}

// Restore layout must come from the manifest. Deriving it from the current
// config lets a machine whose data_dir has since moved rename a tree aside that
// the archive never repopulates.
func TestRestoreTargetsUseManifestLayout(t *testing.T) {
	home := t.TempDir()

	single, err := restoreTargets(home, backupManifest{Roots: []string{"/old/home"}, DataDirNested: true})
	if err != nil {
		t.Fatalf("single-root: %v", err)
	}
	if len(single) != 1 {
		t.Fatalf("single-root targets = %v, want 1", single)
	}

	external := filepath.Join(t.TempDir(), "external-data")
	multi, err := restoreTargets(home, backupManifest{
		Roots: []string{"/old/home", external}, DataDir: external,
	})
	if err != nil {
		t.Fatalf("two-root: %v", err)
	}
	if len(multi) != 2 || multi[1] != external {
		t.Fatalf("two-root targets = %v, want the archived data dir second", multi)
	}
}

// An archive that records two roots but carries neither an absolute second root
// nor a data_dir cannot be placed; refusing beats renaming a tree aside and
// never repopulating it.
func TestRestoreTargetsRefusesUnplaceableLayout(t *testing.T) {
	_, err := restoreTargets(t.TempDir(), backupManifest{Roots: []string{"/a", "relative-root"}})
	if err == nil {
		t.Fatal("archive with an unplaceable second root was accepted")
	}
}

func TestVerifyArchiveHasConsensusState(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"config.yaml": "no chain here"})
	empty := filepath.Join(t.TempDir(), "empty.tar.gz")
	if _, _, err := writeBackupArchive(empty, []string{src}, backupManifest{
		Kind: backupKindFull, ForkVersion: ConsensusForkVersion, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("writeBackupArchive: %v", err)
	}
	if err := verifyArchiveHasConsensusState(empty); err == nil {
		t.Fatal("archive without a badger tree passed consensus-state verification")
	}

	writeTree(t, src, map[string]string{"data/badger/MANIFEST": "x"})
	good := filepath.Join(t.TempDir(), "good.tar.gz")
	if _, _, err := writeBackupArchive(good, []string{src}, backupManifest{
		Kind: backupKindFull, ForkVersion: ConsensusForkVersion, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("writeBackupArchive: %v", err)
	}
	if err := verifyArchiveHasConsensusState(good); err != nil {
		t.Fatalf("archive with a badger tree was rejected: %v", err)
	}
}

// F6/F7 collided: backupRoots resolved a symlinked data_dir into its own root,
// but archiveTree still emitted the link itself with an absolute target, which
// validateSymlinkTarget then rejected — producing an archive our own restore
// refused. Backup must never write an entry restore will not accept.
func TestBackupSkipsSymlinksRestoreWouldReject(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	external := filepath.Join(base, "external")
	if err := os.MkdirAll(filepath.Join(external, "badger"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(external, "badger", "MANIFEST"), []byte("m"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("c"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(external, filepath.Join(home, "data")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	roots, _, err := backupRoots(home, filepath.Join(home, "data"))
	if err != nil {
		t.Fatalf("backupRoots: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "sym.tar.gz")
	if _, _, err := writeBackupArchive(archive, roots, backupManifest{
		Kind: backupKindFull, ForkVersion: ConsensusForkVersion,
		CreatedAt: time.Now().UTC(), Roots: roots, DataDir: external,
	}); err != nil {
		t.Fatalf("writeBackupArchive: %v", err)
	}

	// The round trip must succeed: this is the archive backup just produced.
	outs := []string{filepath.Join(t.TempDir(), "h"), filepath.Join(t.TempDir(), "d")}
	if err := extractBackupArchive(archive, outs); err != nil {
		t.Fatalf("restore rejected an archive this backup produced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outs[1], "badger", "MANIFEST")); err != nil {
		t.Fatalf("external data tree not restored: %v", err)
	}
}

func TestNormalizeSymlinkTarget(t *testing.T) {
	root := "/srv/sage"

	if _, ok := normalizeSymlinkTarget("/elsewhere", "/srv/sage/data", root); ok {
		t.Fatal("absolute target outside the root accepted")
	}
	if _, ok := normalizeSymlinkTarget("../../etc", "/srv/sage/a/b", root); ok {
		t.Fatal("escaping relative target accepted")
	}
	if rel, ok := normalizeSymlinkTarget("sibling", "/srv/sage/a/b", root); !ok || rel != "sibling" {
		t.Fatalf("in-tree relative target = (%q,%v), want (\"sibling\",true)", rel, ok)
	}
	// An absolute target pointing back inside the tree is restorable once made
	// relative; dropping it would silently lose the link and leave the restored
	// node pointing at a path that no longer exists.
	rel, ok := normalizeSymlinkTarget("/srv/sage/realdata", "/srv/sage/data", root)
	if !ok {
		t.Fatal("absolute in-tree target was dropped instead of normalized")
	}
	if rel != "realdata" {
		t.Fatalf("normalized target = %q, want \"realdata\"", rel)
	}
}

// An absolute symlink pointing back inside SAGE_HOME must survive the round
// trip: dropping it left the restored node with a config naming a data_dir that
// no longer existed.
func TestBackupPreservesInTreeAbsoluteSymlink(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "realdata", "badger"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "realdata", "badger", "MANIFEST"), []byte("m"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(filepath.Join(home, "realdata"), filepath.Join(home, "data")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "in-tree.tar.gz")
	if _, _, err := writeBackupArchive(archive, []string{home}, backupManifest{
		Kind: backupKindFull, ForkVersion: ConsensusForkVersion, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("writeBackupArchive: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "restored")
	if err := extractBackupArchive(archive, []string{dest}); err != nil {
		t.Fatalf("restore rejected an archive this backup produced: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "data")); err != nil {
		t.Fatalf("in-tree symlink was not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "data", "badger", "MANIFEST")); err != nil {
		t.Fatalf("restored symlink does not resolve to the data tree: %v", err)
	}
}

// The manifest must record the RESOLVED data root. Recording the symlink path
// made restoreTargets produce overlapping targets and refuse the very archive
// backup had just written.
func TestSymlinkedDataDirRoundTripsThroughRestoreTargets(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	external := filepath.Join(base, "bigvol")
	if err := os.MkdirAll(external, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(home, "data")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	roots, nested, err := backupRoots(home, link)
	if err != nil {
		t.Fatalf("backupRoots: %v", err)
	}
	if nested || len(roots) != 2 {
		t.Fatalf("roots = %v nested = %v, want two disjoint roots", roots, nested)
	}
	// Mirror exactly what runBackupFull persists.
	manifestDataDir := link
	if !nested && len(roots) > 1 {
		manifestDataDir = roots[1]
	}
	targets, err := restoreTargets(home, backupManifest{
		Roots: roots, DataDir: manifestDataDir, DataDirNested: nested,
	})
	if err != nil {
		t.Fatalf("restore refused an archive this backup would produce: %v", err)
	}
	if len(targets) != 2 || pathWithin(targets[1], targets[0]) {
		t.Fatalf("targets = %v, want two disjoint paths", targets)
	}
}

// Restore targets that overlap on this machine would clobber one another. They
// were disjoint when the backup was taken, so refuse rather than destroy.
func TestRestoreTargetsRefusesOverlappingLayout(t *testing.T) {
	// A manifest whose second root genuinely lands inside this machine's
	// SAGE_HOME — e.g. restoring an archive taken as SAGE_HOME=/old with
	// data at /old/data under a SAGE_HOME of /old's parent.
	home := t.TempDir()
	nested := filepath.Join(home, "data")
	_, err := restoreTargets(home, backupManifest{
		Roots: []string{filepath.Join(home, "old"), nested}, DataDir: nested,
	})
	if err == nil {
		t.Fatal("overlapping restore targets were accepted")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("unexpected error %v", err)
	}
}

// The default backup lives inside SAGE_HOME, which restore replaces. Staging it
// outside must make the command backup prints actually work.
func TestStageArchiveOutsideTargets(t *testing.T) {
	home := t.TempDir()
	inside := filepath.Join(home, "backups")
	if err := os.MkdirAll(inside, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	archive := filepath.Join(inside, "a.tar.gz")
	if err := os.WriteFile(archive, []byte("payload"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	staged, err := stageArchiveOutsideTargets(archive, []string{home})
	if err != nil {
		t.Fatalf("stageArchiveOutsideTargets: %v", err)
	}
	defer func() { _ = os.RemoveAll(filepath.Dir(staged)) }()

	if pathWithin(staged, home) {
		t.Fatalf("staged archive %s is still inside the restore target %s", staged, home)
	}
	b, err := os.ReadFile(staged)
	if err != nil || string(b) != "payload" {
		t.Fatalf("staged copy is wrong: %v %q", err, b)
	}
}

// The symlink that points SAGE_HOME/data at an external volume cannot travel
// inside the archive (restore rejects escaping link targets). Restore must
// rebuild it from the manifest, or the restored node's config.yaml names a
// data_dir that no longer exists and it comes up with no chain.
func TestRestoreRecreatesExternalDataDirLink(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	external := filepath.Join(base, "bigvol")
	for _, d := range []string{home, external} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	link := filepath.Join(home, "data")

	manifest := backupManifest{
		Kind: backupKindFull, ForkVersion: ConsensusForkVersion,
		SageHome: home, DataDir: external, DataDirLink: link,
		Roots: []string{home, external},
	}
	if err := restoreDataDirLink(manifest, []string{home, external}); err != nil {
		t.Fatalf("restoreDataDirLink: %v", err)
	}

	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("data_dir symlink was not recreated: %v", err)
	}
	if got != external {
		t.Fatalf("symlink target = %q, want %q", got, external)
	}
}

// A nested (non-symlinked) data_dir records no link, so nothing is recreated.
func TestRestoreDataDirLinkNoopWithoutLink(t *testing.T) {
	home := t.TempDir()
	if err := restoreDataDirLink(backupManifest{SageHome: home}, []string{home}); err != nil {
		t.Fatalf("no-link manifest produced an error: %v", err)
	}
}

// Restore must never clobber something already sitting at the link path.
func TestRestoreDataDirLinkDoesNotClobber(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	external := filepath.Join(base, "bigvol")
	for _, d := range []string{home, external} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	link := filepath.Join(home, "data")
	if err := os.MkdirAll(link, 0700); err != nil {
		t.Fatalf("mkdir link path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(link, "keep"), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := restoreDataDirLink(backupManifest{
		SageHome: home, DataDir: external, DataDirLink: link, Roots: []string{home, external},
	}, []string{home, external}); err != nil {
		t.Fatalf("restoreDataDirLink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(link, "keep")); err != nil {
		t.Fatalf("existing directory at the link path was clobbered: %v", err)
	}
}
