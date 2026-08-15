import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { analyze, describe, coverageCounts } from './doc-citations.mjs';

const baseline = JSON.parse(
  readFileSync(new URL('./doc-citations.baseline.json', import.meta.url), 'utf8'),
);

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
  const counts = coverageCounts(analyze());
  const lost = [];
  for (const [key, expected] of Object.entries(baseline)) {
    const actual = counts[key] ?? 0;
    if (actual < expected) {
      const [doc, symbol, path] = key.split('|');
      lost.push(`${doc}: \`${symbol}\` -> ${path} (checked ${expected}x, now ${actual}x)`);
    }
  }
  assert.deepEqual(lost, [], `${lost.length} citation(s) stopped being checked`);
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
