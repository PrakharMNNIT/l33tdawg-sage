// Resolve the `symbol` + `file.go:line` citations in docs/reference/.
//
// docs/reference/ is the authoritative, code-verified reference: CLAUDE.md
// points agents there BEFORE reading source, and says it supersedes
// api/openapi.yaml and ARCHITECTURE.md where they disagree. That authority
// rests entirely on the citations being true, and a line number is the one
// kind of claim that rots on its own -- every insertion above a function
// silently invalidates every citation below it, with nothing failing.
//
// A citation of the form (`handleGetMemory`, `memory_handler.go:1118`) makes a
// checkable assertion: line 1118 is inside func handleGetMemory. This module
// resolves that assertion; doc-citations.test.mjs enforces it and `--fix`
// repairs it.
//
// Deliberately conservative -- it only checks what it can resolve unambiguously,
// because a guard that cries wolf gets deleted:
//   - the cited path must match exactly one tracked .go file
//   - the symbol must be a top-level func in that file
//   - anything else is SKIPPED, never guessed at and never failed
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

// The tree to resolve citations against. Overridable so the lifecycle tests can
// run the whole guard against an isolated fixture instead of the live repo.
const root = process.env.DOC_CITATIONS_ROOT
  ? `${resolve(process.env.DOC_CITATIONS_ROOT)}/`
  : new URL('../', import.meta.url).pathname;

// `symbol` ... `path/to/file.go:123` (optionally :123-456 or :123+).
//
// The path class allows '-' so a hyphenated directory (cmd/sage-gui) parses,
// and the gap between symbol and path may cross AT MOST ONE newline so a
// citation that prose-wraps across a single line break is still seen. Both were
// silent blind spots: an unmatched citation is not "skipped", it is INVISIBLE,
// and the guard cannot defend a claim it never noticed. Exactly one newline is
// permitted, never two -- a blank line is a paragraph boundary, and associating
// a symbol with a path across a paragraph break is a false citation, not a wrap.
const CITATION = /`([A-Za-z_][A-Za-z0-9_]*)`[^`\n]{0,80}?(?:\n[^`\n]{0,80}?)?`?([A-Za-z0-9_/.-]*[a-z0-9_]\.go):(\d+)(-(\d+))?/g;

// Every `file.go:line` address in the prose, symbol or no symbol. This is the
// raw universe a citation lives in; the difference between it and what CITATION
// resolves is the set of references the guard is blind to (see legacyInventory).
const RAW_REFERENCE = /([A-Za-z0-9_/.-]*[a-z0-9_]\.go):(\d+)/g;

// A top-level func begins at column 0; anything indented is a body line.
const FUNC_DECL = /^func (?:\([^)]*\) )?([A-Za-z0-9_]+)/;

function walk(dir, pred, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, pred, out);
    else if (pred(full)) out.push(full);
  }
  return out;
}

export function goFiles() {
  const skip = new Set(['node_modules', '.git', 'third_party', 'vendor']);
  return walk(root, (p) => p.endsWith('.go'), []).filter(
    (p) => !relative(root, p).split('/').some((s) => skip.has(s)),
  );
}

export function docFiles() {
  return walk(join(root, 'docs/reference'), (p) => p.endsWith('.md'));
}

// Byte offset -> 1-based line number, so a citation that spans a newline can be
// matched over the whole document yet still reported at the line its NUMBER
// sits on (the number is the part that drifts and the part the fixer edits).
function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text[i] === '\n') starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

// Pure citation extraction, decoupled from the filesystem so it can be unit
// tested on fixtures: hyphenated paths and newline-spanning citations must be
// SEEN, which is exactly what regressed when three citations went invisible.
export function matchCitations(text) {
  const lineAt = lineIndex(text);
  const out = [];
  for (const m of text.matchAll(CITATION)) {
    const [, symbol, citedPath, startStr, , endStr] = m;
    const numIndex = m.index + m[0].lastIndexOf(`${citedPath}:${startStr}`);
    out.push({
      symbol,
      citedPath,
      start: Number(startStr),
      end: endStr ? Number(endStr) : null,
      match: m[0],
      index: m.index,
      pathIndex: numIndex, // byte offset of the `path:line` token (aligns with RAW_REFERENCE)
      line: lineAt(numIndex), // line of the number (edit + report anchor)
      symbolLine: lineAt(m.index),
    });
  }
  return out;
}

// Extent of each top-level func, plus the contiguous comment block directly
// above it. Citing the doc comment rather than the `func` line is a normal and
// correct thing for a doc to do, so it counts as inside.
function functionSpans(path) {
  const lines = readFileSync(path, 'utf8').split('\n');
  const decls = [];
  lines.forEach((line, i) => {
    const m = FUNC_DECL.exec(line);
    if (m) decls.push({ name: m[1], start: i + 1 });
  });
  const spans = new Map();
  decls.forEach((decl, i) => {
    const end = i + 1 < decls.length ? decls[i + 1].start - 1 : lines.length;
    let lead = decl.start;
    while (lead > 1 && /^\s*\/\//.test(lines[lead - 2])) lead -= 1;
    const list = spans.get(decl.name) ?? [];
    list.push({ start: decl.start, end, lead });
    spans.set(decl.name, list);
  });
  return spans;
}

// WHERE inside the function a citation lands. The distinction is load-bearing
// for repair: a citation anchored to the `func` line (decl) is just an address
// and can be mechanically re-pointed when it drifts, but a citation aimed at a
// LEAD comment or an INTERIOR body line was chosen to point at specific text,
// and snapping it back to the decl line would silently discard that intent --
// the "interior flattening" the fixer must refuse.
export function anchorKind(start, span) {
  if (start === span.start) return 'decl';
  if (start >= span.lead && start < span.start) return 'lead';
  if (start > span.start && start <= span.end) return 'interior';
  return 'outside';
}

export function analyze() {
  const go = goFiles();
  const spanCache = new Map();
  const spansFor = (p) => {
    if (!spanCache.has(p)) spanCache.set(p, functionSpans(p));
    return spanCache.get(p);
  };

  const results = [];
  for (const doc of docFiles()) {
    const text = readFileSync(doc, 'utf8');
    for (const c of matchCitations(text)) {
      const { symbol, citedPath, start, end, line } = c;
      // Boundary-aware: 'app.go' must not resolve via 'myapp.go'.
      const matches = go.filter((p) => {
        const rel = relative(root, p);
        return rel === citedPath || rel.endsWith(`/${citedPath}`);
      });
      if (matches.length !== 1) {
        results.push({ status: 'skipped', reason: 'path', doc, line, symbol, citedPath });
        continue;
      }
      const spans = spansFor(matches[0]).get(symbol);
      if (!spans) {
        results.push({ status: 'skipped', reason: 'symbol', doc, line, symbol, citedPath });
        continue;
      }
      const host = spans.find((s) => start >= s.lead && start <= s.end) ?? null;
      results.push({
        status: host ? 'ok' : 'wrong',
        kind: host ? anchorKind(start, host) : null,
        doc,
        line,
        symbol,
        citedPath,
        file: relative(root, matches[0]),
        cited: { start, end },
        actual: spans,
        match: c.match,
        index: c.index,
        pathIndex: c.pathIndex,
      });
    }
  }

  // Per-CONCRETE-citation occurrence ordinal under the coverage key, in stable
  // document order. Two citations that share doc|symbol|path but sit at
  // different lines (say a decl anchor and an interior anchor) must not collapse
  // to one anchor entry, or one would silently inherit the other's repair
  // policy. Occurrence order is stable because results are pushed doc-by-doc and
  // in match order within a doc.
  const occ = new Map();
  for (const r of results) {
    const k = coverageKey(r);
    const n = occ.get(k) ?? 0;
    r.occ = n;
    occ.set(k, n + 1);
  }
  return results;
}

// Identity of ONE concrete citation for anchor tracking: its coverage key plus
// its occurrence ordinal, so duplicates under the same key are addressed
// individually rather than merged.
export function anchorId(r) {
  return `${coverageKey(r)}#${r.occ}`;
}

// Stable identity for one citation's COVERAGE, deliberately excluding the doc
// line number: editing prose above a citation must not look like coverage loss.
export function coverageKey(r) {
  return `${relative(root, r.doc)}|${r.symbol}|${r.citedPath}`;
}

// How many citations resolve per key. A key dropping below its baseline count
// means a citation that USED to be checked is no longer checked -- which the
// aggregate floor cannot see, because one citation going from resolved to
// skipped barely moves the total.
export function coverageCounts(results) {
  const counts = {};
  for (const r of results) {
    if (r.status === 'skipped') continue;
    const k = coverageKey(r);
    counts[k] = (counts[k] ?? 0) + 1;
  }
  return counts;
}

// Keys that fell below their pinned coverage: a citation checked at baseline
// time is no longer checked. Pure so the parsed->skipped regression is unit
// testable without mutating real docs.
export function lostCoverage(baseline, counts) {
  const lost = [];
  for (const [key, expected] of Object.entries(baseline)) {
    const actual = counts[key] ?? 0;
    if (actual < expected) {
      const [doc, symbol, path] = key.split('|');
      lost.push(`${doc}: \`${symbol}\` -> ${path} (checked ${expected}x, now ${actual}x)`);
    }
  }
  return lost;
}

// The anchor KIND each resolved citation had when the baseline was taken,
// keyed exactly like coverage. When a citation later drifts out of its function
// the current code can no longer tell what it was aiming at, so the fixer has
// to consult this to know whether a mechanical re-point is safe (decl) or would
// launder away a deliberate lead/interior anchor.
export function anchorKinds(results) {
  const kinds = {};
  for (const r of results) {
    if (r.status !== 'ok') continue;
    kinds[anchorId(r)] = r.kind;
  }
  return kinds;
}

// May the fixer mechanically re-point this drifted citation? Only when the
// baseline recorded THIS concrete citation as a `decl` anchor -- an address
// with no textual intent. A lead/interior anchor, or one with no recorded kind
// at all, is refused and handed to a human, because snapping it to the decl
// line would erase the very thing it was pointing at while looking freshly
// repaired.
export function repairEligibility(r, anchors) {
  const kind = anchors[anchorId(r)];
  if (kind === 'decl') return { fix: true };
  if (!kind) return { fix: false, reason: 'no recorded anchor kind' };
  return { fix: false, reason: `${kind} anchor` };
}

// The raw `file.go:line` references the resolver is BLIND to, tallied per
// (doc, path). "Blind" = present in the prose but not resolved to a symbol:
// either CITATION never matched it (a bare address with no symbol) or it
// matched and skipped (path/symbol unresolvable). Pinning these as an inventory
// makes a NEWLY-added unresolvable reference fail -- "new skipped coverage" --
// while grandfathering the hundreds that already exist, so no mass migration is
// forced by this guard.
export function legacyInventory(results = analyze()) {
  // Mark checked references by concrete BYTE OFFSET, not by line: two references
  // to the same path can share a Markdown line (one parsed, one bare), and a
  // line-keyed set cannot tell them apart -- it would mask the bare one as
  // "checked" and let a new unresolvable reference in silently. The offset is
  // the one the resolver already computed for the path token (pathIndex), which
  // aligns with RAW_REFERENCE.match.index since both point at the path's start.
  const checked = new Set();
  for (const r of results) {
    if (r.status === 'ok' || r.status === 'wrong') {
      checked.add(`${relative(root, r.doc)}|${r.pathIndex}`);
    }
  }
  const inv = {};
  for (const doc of docFiles()) {
    const rel = relative(root, doc);
    const text = readFileSync(doc, 'utf8');
    for (const m of text.matchAll(RAW_REFERENCE)) {
      if (checked.has(`${rel}|${m.index}`)) continue;
      const key = `${rel}|${m[1]}`;
      inv[key] = (inv[key] ?? 0) + 1;
    }
  }
  return inv;
}

// Keys whose blind-reference count rose above baseline, or that are new
// entirely: a reference the guard could not check was introduced or multiplied.
// Pure, for the same fixture-testability reason as lostCoverage.
export function newUnchecked(baseline, inventory) {
  const grown = [];
  for (const [key, count] of Object.entries(inventory)) {
    const allowed = baseline[key] ?? 0;
    if (count > allowed) {
      const [doc, path] = key.split('|');
      grown.push(`${doc}: ${path} (${allowed} unchecked reference(s) allowed, now ${count})`);
    }
  }
  return grown;
}

export function describe(r) {
  const actual = r.actual.map((s) => `${s.start}-${s.end}`).join(', ');
  const cited = r.cited.end ? `${r.cited.start}-${r.cited.end}` : `${r.cited.start}`;
  return `${relative(root, r.doc)}:${r.line}: \`${r.symbol}\` cited at ${r.citedPath}:${cited}, but ${r.symbol} is at ${r.file}:${actual}`;
}
