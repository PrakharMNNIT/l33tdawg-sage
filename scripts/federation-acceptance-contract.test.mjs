import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { findInboxMessage } from './federation-acceptance-find-inbox-message.mjs';

const root = path.resolve(import.meta.dirname, '..');
const base = path.join(root, 'deploy', 'federation-acceptance');
const compose = fs.readFileSync(path.join(base, 'docker-compose.yml'), 'utf8');
const runner = fs.readFileSync(path.join(base, 'run.sh'), 'utf8');
const legacy = fs.readFileSync(path.join(base, 'v11.17.4-config.template.yaml'), 'utf8');

for (const service of ['relay:', 'node-a:', 'node-b:']) assert.match(compose, new RegExp(`\\n  ${service}`));
assert.equal((compose.match(/image: sage-v111800-node:local/g) || []).length, 2,
  'both nodes must run the exact same built image');
for (const network of ['edge_a:', 'edge_b:', 'lan:']) assert.match(compose, new RegExp(`\\n  ${network}`));
assert.match(compose, /SAGE_VENDORED_AGENT_HOME_DOMAIN: mynah-a-home/);
assert.match(compose, /SAGE_VENDORED_AGENT_HOME_DOMAIN: mynah-b-home/);

for (const gate of [
  'same-LAN topology',
  'only the relay bridges',
  'restart A, B, then both',
  'relay outage and recovery',
  'expired route snapshot fixture',
  'v11.17.4 persisted p2p_peers compatibility shape',
  'canonical MCP flow: friendly registered-name send -> reply receipt -> offline inbox -> read -> reply/status',
  'directional peer export read needs no mirrored group',
  'bidirectional Copy: seed pre-consent memories for initial backfill',
  'bidirectional Copy: each owner offers Copy and each receiver independently subscribes',
  'bidirectional Copy: initial anti-entropy backfill',
  'bidirectional Copy: incremental delivery after consent',
  'bidirectional Copy: restart persistence and source-offline local reads',
]) assert.ok(runner.includes(gate), `missing matrix gate: ${gate}`);

assert.match(runner, /automatic real JOIN ceremony over LAN/);
assert.match(runner, /federation\/join\/guest\/confirm/);
assert.match(runner, /sage_find_agent/);
assert.match(runner, /sage_message_send/);
assert.match(runner, /node-a\) project=voice-bridge-a[\s\S]*node-b\) project=voice-bridge-b/,
  'fresh nodes need distinct immutable registered names so the friendly-name gate is not an intentional local/federated collision');
assert.match(runner, /friendly_target=.*registered_name/);
assert.equal((runner.match(/federation-acceptance-find-inbox-message\.mjs/g) || []).length, 2,
  'friendly and offline inbox gates must use the exact correlation helper');
assert.doesNotMatch(runner, /items\.0\.message_id/,
  'inbox order is not a delivery guarantee');
assert.doesNotMatch(runner, /friendly_received_id.*friendly_message_id/,
  'federated delivery intentionally translates the sender-local message ID');

const correlation = {
  intent: 'acceptance',
  payload: 'unique run payload',
  senderAgent: 'agent-a',
  sourceChain: 'chain-a',
};
const translated = findInboxMessage({ items: [
  { message_id: 'stale-local', ...correlation, sender_agent: 'agent-a', source_chain: 'wrong-chain' },
  { message_id: 'msg-fed-receiver-local', intent: correlation.intent, payload: correlation.payload,
    sender_agent: correlation.senderAgent, source_chain: correlation.sourceChain },
  { message_id: 'sender-local-id', intent: correlation.intent, payload: 'other run',
    sender_agent: correlation.senderAgent, source_chain: correlation.sourceChain },
] }, correlation);
assert.equal(translated?.message_id, 'msg-fed-receiver-local',
  'correlation must select the translated receiver-local ID regardless of inbox order');
assert.equal(findInboxMessage({ items: [
  { message_id: 'near-match', intent: correlation.intent, payload: correlation.payload,
    sender_agent: correlation.senderAgent, source_chain: 'wrong-chain' },
] }, correlation), undefined, 'correlation must reject a near-match from the wrong source chain');
assert.match(runner, /reply_event_id/);
assert.match(runner, /reply event status leaked original message workflow/);
assert.match(runner, /friendly_sender_status=.*sage_message_status/);
assert.match(runner, /friendly_read_status.*confirmed/);
assert.match(runner, /friendly_workflow_status.*completed/);
assert.match(runner, /friendly sender status lacks confirmed read and completed reply after retry window/);
assert.match(runner, /transport_status.*queued/);
assert.match(runner, /peer_status.*unconfirmed/);
assert.match(runner, /send_elapsed.*-le 5/);
assert.match(runner, /idempotent_replay.*false/);
assert.match(runner, /sage_inbox/);
assert.match(runner, /sage_message_reply/);
assert.match(runner, /sage_message_status/);
assert.match(runner, /mcp_call node-a sage_remember/);
assert.match(runner, /remember_committed\(\)/);
assert.match(runner, /result\.skipped \|\| result\.status === "skipped" \|\| result\.status === "rejected"/);
assert.match(runner, /!result\.memory_id \|\| result\.committed !== true/);
for (const call of [
  'remember_committed node-a "$remember_a_initial"',
  'remember_committed node-b "$remember_b_initial"',
  'remember_committed node-a "$remember_a_incremental"',
  'remember_committed node-b "$remember_b_incremental"',
]) assert.ok(runner.includes(call), `missing fail-closed source admission: ${call}`);
assert.equal((runner.match(/remember_committed node-[ab] /g) || []).length, 4,
  'every initial and incremental source seed must use the fail-closed admission helper');
const marker = name => runner.match(new RegExp(`${name}="([^"]+)"`))?.[1];
const significant = value => {
  const seen = new Set();
  for (const raw of value.toLowerCase().trim().split(/\s+/)) {
    const word = raw.replace(/^[.,;:!?"'()[\]{}—-]+|[.,;:!?"'()[\]{}—-]+$/g, '');
    if (word.length >= 4) seen.add(word);
  }
  return [...seen];
};
for (const side of ['a', 'b']) {
  const initial = significant(marker(`mirror_${side}_initial`));
  const incremental = significant(marker(`mirror_${side}_incremental`));
  const existing = initial.join(' ').toLowerCase();
  const overlap = incremental.filter(word => existing.includes(word)).length / incremental.length;
  assert.ok(overlap <= 0.60,
    `node ${side.toUpperCase()} incremental fixture would trip the >60% duplicate guard (${overlap})`);
}
assert.match(runner, /connections\/\$chain_a\/agent-exports/);
assert.match(runner, /connections\/\$chain_b\/agent-exports/);
assert.doesNotMatch(runner, /grant reciprocal Mynah home-domain read and exact inbox consent/);
assert.match(runner, /mcp_call node-b sage_federation/);
assert.match(runner, /mcp_call node-b sage_recall/);
assert.match(runner, /network\/access\/linked-readers/);
assert.match(runner, /contains legacy linked-reader state/);
assert.match(runner, /federated-peer-export-read-v1/);
assert.match(runner, /read_authorization!=="verified"/);
assert.match(runner, /read_authorization_complete!==true/);
assert.match(runner, /shared_read_domains/);
assert.doesNotMatch(runner, /echo "\$exported" \| grep -q 'mynah-a-home'/,
  'a candidate-only domain string must not satisfy peer-export acceptance');
assert.match(runner, /ordinary node B companion could not read node A's export without a mirrored group/);
assert.match(runner, /node-a PUT "\/v1\/dashboard\/federation\/connections\/\$chain_a\/permissions" "\$permission_a"/);
assert.match(runner, /node-b PUT "\/v1\/dashboard\/federation\/connections\/\$chain_b\/permissions" "\$permission_b"/);
assert.equal((runner.match(/"copy":true/g) || []).length, 2,
  'both source nodes must explicitly offer Copy for their own domain');
assert.match(runner, /subscribe_a='\{"subscribe_domains":\["mynah-b-home"\]\}'/);
assert.match(runner, /subscribe_b='\{"subscribe_domains":\["mynah-a-home"\]\}'/);
assert.match(runner, /scope:\"local\"/,
  'mirroring must be verified from receiver-local storage, not live federation recall');
for (const call of [
  'wait_local_copy node-b "$mirror_a_initial" mynah-a-home',
  'wait_local_copy node-a "$mirror_b_initial" mynah-b-home',
  'wait_local_copy node-b "$mirror_a_incremental" mynah-a-home',
  'wait_local_copy node-a "$mirror_b_incremental" mynah-b-home',
]) assert.ok(runner.includes(call), `missing receiver-local mirror assertion: ${call}`);
const initialPhase = runner.slice(
  runner.indexOf('phase "bidirectional Copy: initial anti-entropy backfill"'),
  runner.indexOf('phase "bidirectional Copy: incremental delivery after consent"'),
);
assert.ok(initialPhase.includes('wait_local_copy node-b "$mirror_a_initial" mynah-a-home'));
assert.ok(initialPhase.includes('wait_local_copy node-a "$mirror_b_initial" mynah-b-home'));
const incrementalPhase = runner.slice(
  runner.indexOf('phase "bidirectional Copy: incremental delivery after consent"'),
  runner.indexOf('phase "bidirectional Copy: restart persistence and source-offline local reads"'),
);
assert.ok(incrementalPhase.includes('wait_local_copy node-b "$mirror_a_incremental" mynah-a-home'));
assert.ok(incrementalPhase.includes('wait_local_copy node-a "$mirror_b_incremental" mynah-b-home'));
assert.match(runner, /dc stop node-a[\s\S]*wait_local_copy node-b "\$mirror_a_initial"/);
assert.match(runner, /dc stop node-b[\s\S]*wait_local_copy node-a "\$mirror_b_initial"/);
assert.match(runner, /timeout "\$MCP_TIMEOUT_SECONDS" sage-gui mcp/);
assert.match(runner, /\[ "\$app_a" -ge 26 \]/);
assert.match(runner, /\[ "\$app_b" -ge 26 \]/);
assert.match(runner, /read_status.*confirmed/);
assert.match(runner, /workflow_status.*completed/);
assert.match(runner, /v11\.17\.4 p2p_peers did not migrate/);
assert.match(legacy, /p2p_peers:/);
assert.doesNotMatch(legacy, /p2p_routes:/);

console.log('federation acceptance contract: ok');
