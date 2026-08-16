// Repair drifted `symbol` + `file.go:line` citations in docs/reference/.
//
// Usage: node scripts/fix-doc-citations.mjs [--dry-run]
//        node scripts/fix-doc-citations.mjs --update-baseline   (coverage + legacy inventory)
//        node scripts/fix-doc-citations.mjs --update-anchors     (anchor kinds; refuses if drifted)
//
// EXIT STATUS IS LOAD-BEARING. A release/automation caller reads it: the command
// exits nonzero whenever a citation it could not safely repair remains, so
// "printed a warning but exited 0" can never report false success.
//
// SCOPE, AND ITS LIMITS. This repairs WHERE a symbol lives. It cannot verify the
// prose around the citation, and the difference is load-bearing: a stale line
// number where the claim is still true is a clerical error, but a doc that
// QUOTES source text which no longer exists is a false claim, and renumbering
// that one would launder it into something that looks freshly verified.
//
// So the fixer refuses on two grounds and reports to a human instead:
//   - the citation quotes source text absent from the target function, or
//   - the citation was anchored to a LEAD comment or INTERIOR line, not the
//     `func` decl -- re-pointing those to the decl line discards the specific
//     text they were aiming at (interior flattening).
// Fixing the address of a decl citation is mechanical; fixing the claim is not.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze, coverageCounts, anchorKinds, legacyInventory, repairEligibility } from './doc-citations.mjs';

// Root (the tree citations resolve against) and data dir (where the baselines
// live) are both overridable so the lifecycle tests run in an isolated fixture.
const root = process.env.DOC_CITATIONS_ROOT
  ? `${resolve(process.env.DOC_CITATIONS_ROOT)}/`
  : new URL('../', import.meta.url).pathname;
const dataDir = process.env.DOC_CITATIONS_DATA
  ? resolve(process.env.DOC_CITATIONS_DATA)
  : dirname(fileURLToPath(import.meta.url));
const dataPath = (name) => join(dataDir, name);
const dryRun = process.argv.includes('--dry-run');

const writeAnchors = (results) =>
  writeFileSync(dataPath('doc-citations.anchors.json'), `${JSON.stringify(anchorKinds(results), null, 2)}\n`);

// Regenerate the fail-closed coverage baseline and the legacy blind-reference
// inventory. Separated from repair on purpose: repairing drift is routine,
// whereas accepting that a citation is no longer checked -- or that a new
// unresolvable reference now exists -- is a decision someone should make
// deliberately.
if (process.argv.includes('--update-baseline')) {
  const results = analyze();
  writeFileSync(dataPath('doc-citations.baseline.json'), `${JSON.stringify(coverageCounts(results), null, 2)}\n`);
  const inv = legacyInventory(results);
  writeFileSync(dataPath('doc-citations.legacy.json'), `${JSON.stringify(inv, null, 2)}\n`);
  console.log(
    `baseline updated: ${Object.keys(coverageCounts(results)).length} coverage key(s), ` +
      `${Object.keys(inv).length} legacy key(s)`,
  );
  process.exit(0);
}

// Regenerate the anchor-kind baseline. Kept behind its own flag, separate from
// coverage acceptance above. It REFUSES a drifted corpus: analyze() omits wrong
// citations, so snapshotting anchors while any citation is drifted would quietly
// drop those anchors and bless the reduced set as ground truth. Repair first.
if (process.argv.includes('--update-anchors')) {
  const results = analyze();
  const wrong = results.filter((r) => r.status === 'wrong');
  if (wrong.length) {
    console.error(
      `refusing --update-anchors: ${wrong.length} citation(s) are drifted; ` +
        `their anchors would be dropped. Repair drift first (node scripts/fix-doc-citations.mjs).`,
    );
    process.exit(1);
  }
  writeAnchors(results);
  console.log(`anchors updated: ${Object.keys(anchorKinds(results)).length} anchor(s)`);
  process.exit(0);
}

let anchors = {};
try {
  anchors = JSON.parse(readFileSync(dataPath('doc-citations.anchors.json'), 'utf8'));
} catch {
  // No baseline yet: every drifted citation is refused rather than risk
  // flattening one whose intent we cannot reconstruct. Run --update-anchors.
}

// These docs quote source comments in the bold form **"..."**. Only that form
// is treated as a claim about source text; a plain "..." run is ordinary prose
// and matching it spans unrelated quoted phrases, which cries wolf.
const QUOTED = /\*\*"([^"]{25,})"\*\*/g;

const normalize = (s) => s.replace(/[\s/*]+/g, ' ').trim().toLowerCase();

const wrong = analyze().filter((r) => r.status === 'wrong');
const edits = new Map();
const unquotable = [];
const refusedAnchor = [];

for (const r of wrong) {
  const eligible = repairEligibility(r, anchors);
  if (!eligible.fix) {
    refusedAnchor.push({ ...r, reason: eligible.reason });
    continue;
  }

  const docText = readFileSync(r.doc, 'utf8');
  const docLine = docText.split('\n')[r.line - 1] ?? '';
  const target = readFileSync(join(root, r.file), 'utf8').split('\n');
  const span = r.actual[0];
  const body = normalize(target.slice(span.lead - 1, span.end).join(' '));

  let quoteMissing = null;
  for (const q of docLine.matchAll(QUOTED)) {
    const claim = normalize(q[1]);
    if (claim && !body.includes(claim)) quoteMissing = q[1];
  }
  if (quoteMissing) {
    unquotable.push({ ...r, quote: quoteMissing });
    continue;
  }

  // Edit only the number, on the line it sits on -- multi-line-safe, since a
  // newline-spanning citation keeps `path:number` intact on one line.
  const citedTok = r.cited.end ? `${r.cited.start}-${r.cited.end}` : `${r.cited.start}`;
  const newTok = r.cited.end ? `${span.start}-${span.end}` : `${span.start}`;
  const list = edits.get(r.doc) ?? [];
  list.push({ line: r.line, from: `${r.citedPath}:${citedTok}`, to: `${r.citedPath}:${newTok}` });
  edits.set(r.doc, list);
}

let changed = 0;
for (const [doc, list] of edits) {
  const lines = readFileSync(doc, 'utf8').split('\n');
  for (const e of list) {
    const before = lines[e.line - 1];
    const after = before.replace(e.from, e.to);
    if (before !== after) { lines[e.line - 1] = after; changed += 1; }
  }
  if (!dryRun) writeFileSync(doc, lines.join('\n'));
}

console.log(`${dryRun ? 'would repair' : 'repaired'} ${changed} citation(s) across ${edits.size} file(s)`);

// A successful safe repair must keep the anchor baseline current, so the
// citations it just re-pointed stay tracked as decl anchors. Only when the
// repair cleared ALL drift -- a corpus with drift left (refusals) must not
// re-snapshot anchors, same reason --update-anchors refuses one.
if (!dryRun && changed > 0) {
  const after = analyze();
  if (after.filter((r) => r.status === 'wrong').length === 0) {
    writeAnchors(after);
    console.log(`anchors refreshed after repair: ${Object.keys(anchorKinds(after)).length} anchor(s)`);
  }
}

if (refusedAnchor.length) {
  console.log(`\nNOT repaired -- anchored to a lead/interior line, not the func decl.`);
  console.log(`Re-pointing these to the decl line would discard the text they aim at; fix by hand.\n`);
  for (const u of refusedAnchor) {
    console.log(`  ${relative(root, u.doc)}:${u.line}  \`${u.symbol}\` -> ${u.citedPath} (${u.reason})`);
  }
}
if (unquotable.length) {
  console.log(`\nNOT repaired -- these quote source text that is absent from the named function.`);
  console.log(`A wrong line number is clerical; a quote of code that does not exist is a false claim.\n`);
  for (const u of unquotable) {
    console.log(`  ${relative(root, u.doc)}:${u.line}  \`${u.symbol}\` (${u.file}:${u.actual[0].start})`);
    console.log(`     absent quote: "${u.quote.slice(0, 90)}"`);
  }
}

// Fail loud: a drift the tool would not touch still remains, and a caller that
// read exit 0 would take that as "docs are clean."
if (refusedAnchor.length || unquotable.length) process.exit(1);
