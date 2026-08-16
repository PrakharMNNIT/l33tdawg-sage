import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  analyze,
  describe,
  coverageCounts,
  lostCoverage,
  matchCitations,
  legacyInventory,
  newUnchecked,
  anchorId,
  repairEligibility,
} from './doc-citations.mjs';

const readJson = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const baseline = readJson('./doc-citations.baseline.json');
const legacyBaseline = readJson('./doc-citations.legacy.json');

// docs/reference/ is where CLAUDE.md sends agents INSTEAD of reading the source,
// and it supersedes api/openapi.yaml and ARCHITECTURE.md where they disagree.
// Its authority is only as good as its citations, and a line number is the one
// claim that rots with no edit to the doc at all: every insertion above a
// function silently moves everything below it.
//
// Repair drift with: node scripts/fix-doc-citations.mjs
test('docs/reference file:line citations still resolve to the symbol they name', () => {
  const wrong = analyze().filter((r) => r.status === 'wrong');
  assert.deepEqual(wrong.map(describe), [], `${wrong.length} citation(s) drifted`);
});

// FAIL-CLOSED COVERAGE. The previous guard here asserted only that some minimum
// number of citations still resolved, which cannot see coverage eroding one
// citation at a time: rename a cited symbol to something that does not exist and
// that citation silently becomes "skipped" rather than "wrong", the total barely
// moves, and the suite stays green while the claim stops being checked.
//
// The baseline pins coverage PER CITATION, so any citation that is checked today
// and stops being checked tomorrow fails loudly and by name. Deliberately adding
// a new unresolvable reference is still allowed; silently dropping an existing
// checked one is not.
//
// Regenerate after an intentional change with:
//   node scripts/fix-doc-citations.mjs --update-baseline
test('no citation silently loses coverage', () => {
  const lost = lostCoverage(baseline, coverageCounts(analyze()));
  assert.deepEqual(lost, [], `${lost.length} citation(s) stopped being checked`);
});

// FAIL-CLOSED ON THE BLIND SPOT. The resolver ignores ~340 raw `file.go:line`
// references it cannot tie to a symbol; the inventory pins how many blind
// references live per (doc, path) so a NEWLY-added unresolvable reference fails,
// while grandfathering the ones that already exist -- no mass migration, but no
// quiet growth of the unchecked set either.
//
// Regenerate after an intentional change with:
//   node scripts/fix-doc-citations.mjs --update-baseline
test('no new unchecked reference slips in past the legacy inventory', () => {
  const grown = newUnchecked(legacyBaseline, legacyInventory());
  assert.deepEqual(grown, [], `${grown.length} (doc, path) group(s) gained unchecked references`);
});

// SEMANTIC ANCHORS, not just resolvable ones. A citation can point at a real
// function and still be wrong about which function implements the claim. These
// three sentences describe federated COMPLETION -- no journal, and the result
// paired with its durable return-outbox event -- which lives in the result path,
// not the send path. They were briefly anchored to handlePipeSend, which resolves
// perfectly well and is the wrong function, so resolvability alone cannot defend
// them.
test('federated-completion prose stays anchored to the completion path', () => {
  const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
  const restApi = read('docs/reference/rest-api.md');
  const fedApi = read('docs/reference/federation-and-brain-api.md');

  // "never automatically journaled" is decided by shouldAutoJournalPipeline
  assert.match(restApi, /never automatically journaled[\s\S]{0,400}?`shouldAutoJournalPipeline`/);
  // "Federated completion does not journal and queues the result" is handlePipeResult
  assert.match(restApi, /Federated completion does not journal[\s\S]{0,400}?`handlePipeResult`/);
  // "result is atomically paired with its durable return outbox event"
  assert.match(fedApi, /atomically paired with its durable return outbox event[\s\S]{0,400}?`handlePipeResult`/);

  for (const [name, body] of [['rest-api.md', restApi], ['federation-and-brain-api.md', fedApi]]) {
    assert.ok(
      !/(does not journal|atomically paired)[\s\S]{0,400}?`handlePipeSend`/.test(body),
      `${name}: federated-completion prose must not cite the send path`,
    );
  }
});

// ---------------------------------------------------------------------------
// Mutation proofs: the guard has to FAIL on the exact silent paths it exists to
// close. Each constructs the regression and asserts the machinery catches it.
// ---------------------------------------------------------------------------

// (1) PER-CONCRETE-CITATION IDENTITY. Two citations that share doc|symbol|path
// but sit at different lines must be tracked separately: a decl anchor and an
// interior anchor under one key must NOT collapse, or the interior one would
// inherit the decl's mechanical-repair policy (interior flattening).
test('mixed-kind duplicates under one coverage key keep separate anchors', () => {
  const base = { doc: new URL('../docs/reference/dup.md', import.meta.url).pathname, symbol: 'Foo', citedPath: 'internal/x.go' };
  const first = { ...base, occ: 0 };
  const second = { ...base, occ: 1 };
  assert.notEqual(anchorId(first), anchorId(second), 'duplicates must have distinct anchor ids');

  const anchors = { [anchorId(first)]: 'decl', [anchorId(second)]: 'interior' };
  assert.equal(repairEligibility(first, anchors).fix, true, 'the decl occurrence repairs');
  assert.equal(repairEligibility(second, anchors).fix, false, 'the interior occurrence is refused, not flattened');
});

// (2) HYPHEN, SINGLE NEWLINE, AND THE PARAGRAPH BOUNDARY. Hyphenated dirs and a
// single-newline wrap were INVISIBLE to the old regex; both must now be seen.
// But the gap must stop at ONE newline -- a blank line is a paragraph boundary,
// and associating a symbol with a path across it is a false citation, not a wrap.
test('hyphen and single-newline citations are seen; a paragraph break is not crossed', () => {
  const hyphen = matchCitations('see `Boot` in `cmd/sage-gui/main.go:12`');
  assert.equal(hyphen.length, 1, 'hyphenated cmd/sage-gui path must be seen');
  assert.equal(hyphen[0].citedPath, 'cmd/sage-gui/main.go');

  const wrapped = matchCitations('the `handlePipeResult` completion path\n(`internal/federation/x.go:88`).');
  assert.equal(wrapped.length, 1, 'single-newline citation must be seen');
  assert.equal(wrapped[0].line, 2, 'reported at the line the number sits on');

  const paragraph = matchCitations('`Foo` closes a paragraph.\n\nAn unrelated `internal/y.go:9` opens the next.');
  assert.equal(paragraph.length, 0, 'a symbol and a path across a blank line must not associate');
});

// (3) PARSED -> SKIPPED. A citation checked today that stops resolving tomorrow
// (symbol renamed away, file moved) drops out of coverage counts; the per-key
// baseline must catch that even though the aggregate total barely moves.
test('a citation that stops being checked fails the coverage baseline', () => {
  const pinned = { 'docs/reference/x.md|Foo|internal/x.go': 1 };
  assert.deepEqual(lostCoverage(pinned, { 'docs/reference/x.md|Foo|internal/x.go': 1 }), []);
  const dropped = lostCoverage(pinned, {});
  assert.equal(dropped.length, 1, 'a resolved citation going skipped must be reported');
});

// ---------------------------------------------------------------------------
// (4) LIFECYCLE, END TO END through the CLI in an isolated fixture. These prove
// the exit status and the self-maintaining baseline -- the failures the unit
// tests above cannot see because they never run the command.
// ---------------------------------------------------------------------------

const FIXER = fileURLToPath(new URL('./fix-doc-citations.mjs', import.meta.url));

// thing.go: Alpha's decl is line 4, its body (interior) lines 5-8; Beta's decl
// is line 9, its body (interior) lines 10-12.
const GO = [
  'package pkg',
  '',
  '// Alpha does a thing.',
  'func Alpha() {',
  '\tx := 1',
  '\t_ = x',
  '}',
  '',
  'func Beta() {',
  '\ty := 2',
  '\t_ = y',
  '}',
  '',
].join('\n');

const doc = (alphaLine, betaLine) =>
  `# Fixture\n\nThe \`Alpha\` entry point (\`pkg/thing.go:${alphaLine}\`).\n\nThe \`Beta\` body line (\`pkg/thing.go:${betaLine}\`).\n`;

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'doccite-'));
  mkdirSync(join(root, 'docs/reference'), { recursive: true });
  mkdirSync(join(root, 'pkg'), { recursive: true });
  writeFileSync(join(root, 'pkg/thing.go'), GO);
  const env = { ...process.env, DOC_CITATIONS_ROOT: root, DOC_CITATIONS_DATA: root };
  const run = (...args) => {
    try {
      return { code: 0, out: execFileSync('node', [FIXER, ...args], { env, encoding: 'utf8' }) };
    } catch (e) {
      return { code: e.status ?? 1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
    }
  };
  const anchors = () => JSON.parse(readFileSync(join(root, 'doc-citations.anchors.json'), 'utf8'));
  const setDoc = (a, b) => writeFileSync(join(root, 'docs/reference/f.md'), doc(a, b));
  return { root, run, anchors, setDoc, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

// A bare reference sharing a Markdown line with a parsed citation to the SAME
// path must still be counted by the legacy inventory. A line-keyed "checked"
// set masks it (both references map to the same doc|path|line), letting a new
// unresolvable reference slip in silently; keying by byte offset distinguishes
// the concrete occurrences. Run through --update-baseline so it exercises the
// real legacyInventory() with root pointed at the fixture.
test('a bare reference on a parsed citation line is not masked in the inventory', () => {
  const root = mkdtempSync(join(tmpdir(), 'doccite-legacy-'));
  try {
    mkdirSync(join(root, 'docs/reference'), { recursive: true });
    mkdirSync(join(root, 'pkg'), { recursive: true });
    writeFileSync(join(root, 'pkg/x.go'), 'package pkg\n\nfunc Foo() {\n\t_ = 1\n}\n'); // Foo at line 3
    // one Markdown line: a parsed Foo -> pkg/x.go:3, plus a newly added bare pkg/x.go:99
    writeFileSync(join(root, 'docs/reference/a.md'), '# a\n\nThe `Foo` function (`pkg/x.go:3`) — see also pkg/x.go:99.\n');

    const env = { ...process.env, DOC_CITATIONS_ROOT: root, DOC_CITATIONS_DATA: root };
    execFileSync('node', [FIXER, '--update-baseline'], { env, encoding: 'utf8' });
    const inv = JSON.parse(readFileSync(join(root, 'doc-citations.legacy.json'), 'utf8'));

    assert.equal(inv['docs/reference/a.md|pkg/x.go'], 1, 'the bare second occurrence is counted, not masked');
    assert.equal(newUnchecked({}, inv).length >= 1, true, 'and it fails against a prior baseline that did not have it');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// A drifted lead/interior citation the fixer will not touch must make the
// COMMAND fail, not just print a warning -- Dhillon's exact repro: an interior
// citation moved off its line, `--dry-run` printed NOT repaired but exited 0.
test('the fixer exits nonzero when a refused citation remains', () => {
  const s = sandbox();
  try {
    s.setDoc(4, 11); // Alpha=decl@4, Beta=interior@11
    assert.equal(s.run('--update-anchors').code, 0, 'clean corpus accepts anchors');

    s.setDoc(4, 99); // drift Beta's interior citation off its function
    const res = s.run('--dry-run');
    assert.match(res.out, /NOT repaired/, 'the interior refusal is reported');
    assert.equal(res.code, 1, 'a refused citation must fail the command, not exit 0');
  } finally {
    s.cleanup();
  }
});

// --update-anchors must refuse a drifted corpus: regenerating while a citation
// is wrong would drop its anchor (analyze omits wrong) and bless the reduced set.
test('--update-anchors refuses to snapshot a drifted corpus', () => {
  const s = sandbox();
  try {
    s.setDoc(4, 11);
    assert.equal(s.run('--update-anchors').code, 0);

    s.setDoc(99, 11); // drift Alpha's decl citation
    const res = s.run('--update-anchors');
    assert.equal(res.code, 1, 'a drifted corpus must not be blessed');
    assert.match(res.out, /refusing --update-anchors/);
  } finally {
    s.cleanup();
  }
});

// A successful safe repair must refresh the anchor baseline so the citation it
// re-pointed stays tracked, and stale entries do not survive. We seed a ghost
// anchor, repair a decl drift, and assert the refresh regenerated the file:
// the ghost is gone and the repaired citation is present.
test('a successful repair refreshes anchors, dropping stale entries', () => {
  const s = sandbox();
  try {
    s.setDoc(4, 11);
    assert.equal(s.run('--update-anchors').code, 0);

    const seeded = { ...s.anchors(), 'docs/reference/ghost.md|Ghost|pkg/ghost.go#0': 'decl' };
    writeFileSync(join(s.root, 'doc-citations.anchors.json'), `${JSON.stringify(seeded, null, 2)}\n`);

    s.setDoc(99, 11); // drift Alpha's DECL citation -> repairable
    const res = s.run();
    assert.equal(res.code, 0, 'a clean decl repair succeeds');
    assert.match(res.out, /anchors refreshed after repair/);

    const after = s.anchors();
    assert.ok(!('docs/reference/ghost.md|Ghost|pkg/ghost.go#0' in after), 'stale ghost anchor is dropped');
    assert.ok(
      Object.keys(after).some((k) => k.includes('|Alpha|pkg/thing.go#0')),
      'the repaired citation remains tracked',
    );
    assert.match(readFileSync(join(s.root, 'docs/reference/f.md'), 'utf8'), /pkg\/thing\.go:4\b/);
  } finally {
    s.cleanup();
  }
});
