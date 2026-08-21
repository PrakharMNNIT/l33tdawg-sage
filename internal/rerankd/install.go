package rerankd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Managed engine install: SAGE downloads a pinned llama.cpp release build
// itself - no package manager, no sudo, no terminal - the same treatment the
// model gets. Assets are the official ggml-org/llama.cpp GitHub release
// binaries; each sha256 below was computed from the asset fetched over TLS at
// pin time, and is re-verified on every user install so a tampered or
// truncated archive never lands.

const engineRelease = "b9870"

type engineAsset struct {
	name   string
	sha256 string
	size   int64
	format string // "tar.gz" | "zip"
}

// engineAssets maps GOOS/GOARCH to the pinned release asset. CPU builds are
// plenty for a 568M cross-encoder; the macOS arm64 build ships Metal.
var engineAssets = map[string]engineAsset{
	"darwin/arm64":  {"llama-b9870-bin-macos-arm64.tar.gz", "9384fc29bfad58a665a617f3c5e490d5ab9f1f5506383b011d912f1bcc92804a", 11138009, "tar.gz"},
	"darwin/amd64":  {"llama-b9870-bin-macos-x64.tar.gz", "8f12b275bec2083caa13643471bd86083549659f48b2d1fad72c61e84bd5ee59", 11452018, "tar.gz"},
	"linux/amd64":   {"llama-b9870-bin-ubuntu-x64.tar.gz", "16897263ccd016dd76c72a4d9b6ee27f975dae19bf652b4855b37dffbe7d4df1", 15865283, "tar.gz"},
	"linux/arm64":   {"llama-b9870-bin-ubuntu-arm64.tar.gz", "227564dead2145adf388d8fe3edbee8aeeea61e53cb151d03375661885ad8b1b", 12866132, "tar.gz"},
	"windows/amd64": {"llama-b9870-bin-win-cpu-x64.zip", "71be86e7af277e9503847c6050948ecd943d5e34b941e178a8af0c161b2d9a9e", 17486964, "zip"},
	"windows/arm64": {"llama-b9870-bin-win-cpu-arm64.zip", "97b77bfbfd1889da5485552d0103f1e73a13b9ec4dfe924bf6d98543d225dab1", 11378592, "zip"},
}

// maxExtractedBytes caps total decompressed output (archive-bomb guard). The
// real archives decompress to ~27-60MB.
const maxExtractedBytes = 512 << 20

// Test seams.
var (
	engineBaseURL  = "https://github.com/ggml-org/llama.cpp/releases/download/" + engineRelease + "/"
	engineAssetFor = func() (engineAsset, bool) {
		// effectiveArch, not runtime.GOARCH: an x86_64 SAGE build running
		// under Rosetta on Apple Silicon must still fetch the NATIVE arm64
		// engine - the sidecar is its own process, and the arm64 build is
		// the one with Metal.
		a, ok := engineAssets[runtime.GOOS+"/"+effectiveArch()]
		return a, ok
	}
)

// serverBinaryName is the llama-server file name on this platform.
func serverBinaryName() string {
	if runtime.GOOS == "windows" {
		return "llama-server.exe"
	}
	return "llama-server"
}

// engineDir is where the managed engine lives (all release files flattened,
// so the dylib/dll @rpath lookup next to the binary just works).
func (m *Manager) engineDir() string { return filepath.Join(m.dataDir, "llama.cpp") }

// managedBinaryPath is the managed llama-server, present or not.
func (m *Manager) managedBinaryPath() string {
	return filepath.Join(m.engineDir(), serverBinaryName())
}

// EngineInstalled reports whether the managed engine is present.
func (m *Manager) EngineInstalled() bool {
	st, err := os.Stat(m.managedBinaryPath())
	return err == nil && !st.IsDir()
}

// InstallSupported reports whether a pinned release asset exists for this
// platform (when false, the UI falls back to manual-install guidance).
func (m *Manager) InstallSupported() bool {
	_, ok := engineAssetFor()
	return ok
}

// EngineSizeBytes is the pinned download size for this platform (0 when
// unsupported) so the UI can show an honest number before consent.
func (m *Manager) EngineSizeBytes() int64 {
	a, ok := engineAssetFor()
	if !ok {
		return 0
	}
	return a.size
}

// InstallEngine downloads the pinned release archive, verifies its sha256,
// and extracts it into engineDir. Idempotent: returns immediately when the
// managed binary is already present.
func (m *Manager) InstallEngine(ctx context.Context, progress func(done, total int64)) error {
	if m.EngineInstalled() {
		return m.preflightEngine(ctx)
	}
	// Guard against concurrent installs racing on the shared .part dir and
	// rename (same pattern as Download). Without it, a second call's
	// RemoveAll(tmpDir)/RemoveAll(engineDir) can delete the tree an earlier
	// call is still extracting into.
	m.dlMu.Lock()
	if m.installing {
		m.dlMu.Unlock()
		return fmt.Errorf("an engine install is already in progress")
	}
	m.installing = true
	m.dlMu.Unlock()
	defer func() {
		m.dlMu.Lock()
		m.installing = false
		m.dlMu.Unlock()
	}()
	asset, ok := engineAssetFor()
	if !ok {
		return fmt.Errorf("no pinned llama.cpp build for %s/%s - install llama.cpp manually (brew install llama.cpp) and rerun setup", runtime.GOOS, runtime.GOARCH)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, engineBaseURL+asset.name, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return fmt.Errorf("download engine: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download engine: http %d", resp.StatusCode)
	}

	// Small archive (~11-17MB): buffer in memory while hashing so we verify
	// BEFORE any byte touches disk.
	hasher := sha256.New()
	var buf bytes.Buffer
	var done int64
	rdBuf := make([]byte, 256<<10)
	for {
		n, rerr := resp.Body.Read(rdBuf)
		if n > 0 {
			buf.Write(rdBuf[:n])
			_, _ = hasher.Write(rdBuf[:n])
			done += int64(n)
			if done > asset.size {
				return fmt.Errorf("engine archive larger than pinned size - refusing it")
			}
			if progress != nil {
				progress(done, asset.size)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("download engine: %w", rerr)
		}
	}
	if done != asset.size {
		return fmt.Errorf("engine download incomplete: got %d of %d bytes", done, asset.size)
	}
	if sum := hex.EncodeToString(hasher.Sum(nil)); sum != asset.sha256 {
		return fmt.Errorf("engine checksum mismatch (got %s) - refusing to install it", sum)
	}

	// Extract into a temp dir, then atomically move into place.
	tmpDir := m.engineDir() + ".part"
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("create engine dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // no-op after the success rename

	var xerr error
	if asset.format == "zip" {
		xerr = extractZipFlat(buf.Bytes(), tmpDir)
	} else {
		xerr = extractTarGzFlat(bytes.NewReader(buf.Bytes()), tmpDir)
	}
	if xerr != nil {
		return fmt.Errorf("extract engine: %w", xerr)
	}
	if st, err := os.Stat(filepath.Join(tmpDir, serverBinaryName())); err != nil || st.IsDir() {
		return fmt.Errorf("engine archive did not contain %s", serverBinaryName())
	}
	// Belt-and-braces: if another install won the race while we were extracting,
	// leave its engine in place rather than RemoveAll/Rename over it.
	if m.EngineInstalled() {
		return m.preflightEngine(ctx)
	}
	_ = os.RemoveAll(m.engineDir())
	if err := os.Rename(tmpDir, m.engineDir()); err != nil {
		return fmt.Errorf("install engine: %w", err)
	}
	return m.preflightEngine(ctx)
}

// EngineIncompatibleError means the managed engine downloaded and extracted
// cleanly but cannot LOAD on this host: the dynamic loader rejected it because
// the host's C/C++ runtime is older than the prebuilt asset requires. Distinct
// from a download/extract failure — the bytes are correct, the host is too old
// for this build. Callers should route the operator to a bring-your-own reranker
// rather than retrying the managed install.
type EngineIncompatibleError struct {
	OS, Arch string
	Detail   string // the loader's own message, e.g. "version `GLIBC_2.38' not found"
}

func (e *EngineIncompatibleError) Error() string {
	return fmt.Sprintf(
		"managed reranker engine cannot run on this host (%s/%s): %s. "+
			"The prebuilt engine needs a newer C/C++ runtime than this host provides "+
			"(the pinned linux/arm64 llama.cpp build is compiled on a newer base than the "+
			"amd64 one, so an older-glibc arm64 host such as a Jetson on Ubuntu 22.04 hits this). "+
			"Bring your own instead: run your own llama-server and set SAGE_RERANK_ENABLED=1, "+
			"SAGE_RERANK_KIND=llamacpp, and SAGE_RERANK_URL to its address.",
		e.OS, e.Arch, e.Detail)
}

// preflightEngine confirms the freshly-installed managed binary can actually
// LOAD on this host, not merely that it downloaded and extracted. The install
// verifies a sha256 and lands bytes on disk; that is silent about whether the
// dynamic loader can satisfy the binary's C/C++ runtime requirements. On a host
// with an older glibc than the build base (JetPack-6 / Ubuntu 22.04 on a Jetson,
// against the Ubuntu-24.04-built arm64 asset) the engine never execs and the
// operator sees only a dead engine with no cause. Running the binary with a
// trivial flag surfaces the loader's own message so InstallEngine can fail with
// the real reason instead of reporting success.
func (m *Manager) preflightEngine(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.managedBinaryPath(), "--version")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		// Only convert a PROVEN dynamic-loader/libc version mismatch into an
		// incompatibility. Any other non-zero exit (an unrecognized flag on some
		// future build, a timeout) is not proof the host is too old, so it must
		// not block an otherwise-good install on an ambiguous signal.
		if isLoaderVersionFailure(stderr.String()) {
			return &EngineIncompatibleError{
				OS:     runtime.GOOS,
				Arch:   effectiveArch(),
				Detail: firstLine(stderr.String()),
			}
		}
	}
	return nil
}

// isLoaderVersionFailure recognizes the dynamic loader rejecting a binary because
// the host's C/C++ runtime is too old. These tokens are emitted by ld.so and
// libstdc++ themselves (e.g. "version `GLIBC_2.38' not found",
// "`GLIBCXX_3.4.32' not found", "CXXABI_1.3.15 not found") and appear only in a
// version-mismatch loader error, so matching them does not false-positive on
// ordinary program output.
func isLoaderVersionFailure(stderr string) bool {
	s := strings.ToUpper(stderr)
	return strings.Contains(s, "GLIBC_") ||
		strings.Contains(s, "GLIBCXX_") ||
		strings.Contains(s, "CXXABI_")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// extractTarGzFlat writes every regular file's BASENAME into dst. Flattening
// sidesteps path traversal entirely (no archive-controlled directories) and
// matches the release layout, where everything lives in one folder anyway.
//
// Symlinks get a restricted treatment instead of a blanket skip, because the
// dylib soname chain depends on them (llama-server links
// @rpath/libllama-common.0.dylib, which the archive ships as a symlink to
// the versioned real file - dropping it breaks dyld at spawn). A symlink is
// materialized ONLY as basename -> basename within dst, and only when the
// target landed as a regular file from this same archive; anything else
// (absolute targets, ../ escapes, dangling links) is dropped.
func extractTarGzFlat(r io.Reader, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var total int64
	links := map[string]string{} // link basename -> target basename
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name, ok := safeFlatArchiveName(hdr.Name)
		if !ok {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			total += hdr.Size
			if total > maxExtractedBytes {
				return fmt.Errorf("archive expands past the %dMB safety cap", maxExtractedBytes>>20)
			}
			mode := os.FileMode(0o644)
			if hdr.FileInfo().Mode()&0o111 != 0 {
				mode = 0o755
			}
			path, pErr := safeArchivePath(dst, name)
			if pErr != nil {
				return pErr
			}
			if err := writeLimitedFile(path, tr, hdr.Size, mode); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			target, ok := safeFlatArchiveName(hdr.Linkname)
			if !ok || target == name {
				continue
			}
			links[name] = target
		}
	}
	// Second pass: materialize the intra-archive links whose targets exist.
	// Soname chains are links-to-links (libX.dylib -> libX.0.dylib ->
	// libX.0.0.N.dylib), so resolve each target THROUGH the link map to the
	// underlying regular file first (cycle-capped), then point every link
	// straight at it.
	resolve := func(t string) string {
		for i := 0; i < 8; i++ {
			next, ok := links[t]
			if !ok {
				return t
			}
			t = next
		}
		return "" // cycle
	}
	for name, rawTarget := range links {
		target := resolve(rawTarget)
		if target == "" || target == name {
			continue
		}
		targetPath, pErr := safeArchivePath(dst, target)
		if pErr != nil {
			return pErr
		}
		st, err := os.Stat(targetPath)
		if err != nil || !st.Mode().IsRegular() {
			continue // dangling or hostile - drop it
		}
		linkPath, pErr := safeArchivePath(dst, name)
		if pErr != nil {
			return pErr
		}
		if os.Symlink(target, linkPath) != nil {
			// Filesystem without symlinks: copy the bytes instead.
			data, rerr := os.ReadFile(targetPath)
			if rerr != nil {
				return rerr
			}
			//nolint:gosec // linkPath is dst plus a sanitized basename; target was verified inside dst.
			if werr := os.WriteFile(linkPath, data, st.Mode().Perm()); werr != nil {
				return werr
			}
		}
	}
	return nil
}

// extractZipFlat is the zip twin of extractTarGzFlat.
func extractZipFlat(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue
		}
		name, ok := safeFlatArchiveName(f.Name)
		if !ok {
			continue
		}
		total += int64(f.UncompressedSize64)
		if total > maxExtractedBytes {
			return fmt.Errorf("archive expands past the %dMB safety cap", maxExtractedBytes>>20)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if f.Mode()&0o111 != 0 || strings.HasSuffix(name, ".exe") {
			mode = 0o755
		}
		path, pErr := safeArchivePath(dst, name)
		if pErr != nil {
			_ = rc.Close()
			return pErr
		}
		werr := writeLimitedFile(path, rc, int64(f.UncompressedSize64), mode)
		_ = rc.Close()
		if werr != nil {
			return werr
		}
	}
	return nil
}

func safeFlatArchiveName(raw string) (string, bool) {
	clean := filepath.Clean(raw)
	if clean == "." || clean == ".." || filepath.IsAbs(clean) ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	name := filepath.Base(clean)
	if name == "." || name == ".." || name == "" || strings.HasPrefix(name, ".") {
		return "", false
	}
	return name, true
}

func safeArchivePath(dst, name string) (string, error) {
	if _, ok := safeFlatArchiveName(name); !ok {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	root := filepath.Clean(dst)
	path := filepath.Join(root, name)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || filepath.IsAbs(rel) ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return path, nil
}

// writeLimitedFile copies exactly up to size+1 bytes (catching lying
// headers) into path with the given mode.
func writeLimitedFile(path string, r io.Reader, size int64, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	n, cerr := io.Copy(f, io.LimitReader(r, size+1))
	if err := f.Close(); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if n > size {
		return fmt.Errorf("%s: content exceeds declared size", filepath.Base(path))
	}
	return nil
}
