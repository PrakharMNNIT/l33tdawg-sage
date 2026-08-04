import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const base = path.join(root, 'deploy', 'federation-acceptance');
const compose = fs.readFileSync(path.join(base, 'docker-compose.yml'), 'utf8');
const runner = fs.readFileSync(path.join(base, 'run.sh'), 'utf8');
const legacy = fs.readFileSync(path.join(base, 'v11.17.4-config.template.yaml'), 'utf8');

for (const service of ['relay:', 'node-a:', 'node-b:']) assert.match(compose, new RegExp(`\\n  ${service}`));
assert.equal((compose.match(/image: sage-v11176-node:local/g) || []).length, 2,
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
  'canonical MCP flow: find -> send -> offline inbox -> read -> reply/status',
]) assert.ok(runner.includes(gate), `missing matrix gate: ${gate}`);

assert.match(runner, /automatic real JOIN ceremony over LAN/);
assert.match(runner, /federation\/join\/guest\/confirm/);
assert.match(runner, /sage_find_agent/);
assert.match(runner, /sage_message_send/);
assert.match(runner, /transport_status.*queued/);
assert.match(runner, /peer_status.*unconfirmed/);
assert.match(runner, /send_elapsed.*-le 5/);
assert.match(runner, /idempotent_replay.*false/);
assert.match(runner, /sage_inbox/);
assert.match(runner, /sage_message_reply/);
assert.match(runner, /sage_message_status/);
assert.match(runner, /timeout "\$MCP_TIMEOUT_SECONDS" sage-gui mcp/);
assert.match(runner, /\[ "\$app_a" -ge 26 \]/);
assert.match(runner, /\[ "\$app_b" -ge 26 \]/);
assert.match(runner, /read_status.*confirmed/);
assert.match(runner, /workflow_status.*completed/);
assert.match(runner, /v11\.17\.4 p2p_peers did not migrate/);
assert.match(legacy, /p2p_peers:/);
assert.doesNotMatch(legacy, /p2p_routes:/);

console.log('federation acceptance contract: ok');
