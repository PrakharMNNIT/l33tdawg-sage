#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
COMPOSE="$ROOT/deploy/federation-acceptance/docker-compose.yml"
STATE=${FED_ACCEPTANCE_STATE:-/tmp/sage-v11176-federation-state}
MODE=${1:-full}
PORT_A=${FED_NODE_A_PORT:-28080}
PORT_B=${FED_NODE_B_PORT:-28081}
export FED_ACCEPTANCE_STATE=$STATE
export FED_NODE_A_PORT=$PORT_A FED_NODE_B_PORT=$PORT_B
CHURN_IDS=""
MCP_TIMEOUT_SECONDS=${FED_ACCEPTANCE_MCP_TIMEOUT_SECONDS:-100}
RUN_TOKEN=${FED_ACCEPTANCE_RUN_TOKEN:-$(date +%s)-$$}

dc() { docker compose -f "$COMPOSE" "$@"; }
die() { echo "federation acceptance: $*" >&2; exit 1; }
phase() { echo "==> $*"; }
api() { dc exec -T "$1" federation-acceptance-client "$2" "$3" "${4:-}"; }
jfield() {
  node -e 'let v=JSON.parse(process.argv[1]); for (const k of process.argv[2].split(".")) v=v[k]; process.stdout.write(typeof v === "string" ? v : JSON.stringify(v))' "$1" "$2"
}
mcp_call() {
  svc=$1 tool=$2 args=$3
  init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fed-acceptance","version":"1"}}}'
  inception='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sage_inception","arguments":{}}}'
  call=$(node -e 'process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:3,method:"tools/call",params:{name:process.argv[1],arguments:JSON.parse(process.argv[2])}}))' "$tool" "$args")
  out=$(printf '%s\n%s\n%s\n' "$init" "$inception" "$call" | dc exec -T \
    -e SAGE_PROVIDER=mynah -e SAGE_PROJECT=voice-bridge \
    -e SAGE_IDENTITY_PATH=/root/.sage/agents/mynah/agent.key "$svc" \
    timeout "$MCP_TIMEOUT_SECONDS" sage-gui mcp) ||
    die "MCP tool $tool on $svc failed or exceeded ${MCP_TIMEOUT_SECONDS}s"
  node -e 'const lines=process.argv[1].trim().split(/\n/); const r=JSON.parse(lines.at(-1)); if(r.error) throw new Error(JSON.stringify(r.error)); const t=r.result.content[0].text; try { process.stdout.write(JSON.stringify(JSON.parse(t))) } catch { process.stdout.write(t) }' "$out"
}
wait_health() {
  url=$1
  i=0
  until curl -fsS "$url/health" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 90 ] || die "$url did not become healthy"
    sleep 1
  done
}
container_id() { dc ps -q "$1"; }
container_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$(container_id "$1")"
}
lan_ip() {
  docker inspect -f '{{(index .NetworkSettings.Networks "sage-v11176-federation-lan").IPAddress}}' "$(container_id "$1")"
}

cleanup() {
  dc down --remove-orphans >/dev/null 2>&1 || true
  for cid in $CHURN_IDS; do docker stop "$cid" >/dev/null 2>&1 || true; done
  docker network rm sage-v11176-federation-lan >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

case "$STATE" in /tmp/*|/private/tmp/*) ;; *) die "state must be below /tmp (got $STATE)";; esac
mkdir -p "$STATE/a" "$STATE/b" "$STATE/relay"

phase "build relay and one shared SAGE image"
if [ "${FED_ACCEPTANCE_SKIP_BUILD:-0}" != 1 ]; then dc build relay node-a; fi
phase "start isolated relay"
dc up -d relay
i=0
while :; do
  RELAY_ADDR=$(dc logs relay 2>&1 | sed -n 's|.*\(/dns4/relay/tcp/4001/p2p/[A-Za-z0-9]*\).*|\1|p' | head -1)
  [ -n "$RELAY_ADDR" ] && break
  i=$((i + 1)); [ "$i" -lt 60 ] || die "could not discover relay peer ID"
  sleep 1
done

render_config() {
  name=$1 dir=$2
  sed -e "s|__RELAY_ADDR__|$RELAY_ADDR|g" -e "s|__NETWORK_NAME__|$name|g" \
    "$ROOT/deploy/federation-acceptance/config.template.yaml" > "$dir/config.yaml"
}
[ -f "$STATE/a/config.yaml" ] || render_config docker-a "$STATE/a"
[ -f "$STATE/b/config.yaml" ] || render_config docker-b "$STATE/b"

phase "start nodes on different private networks (relay-only reachability)"
dc up -d node-a node-b
wait_health "http://127.0.0.1:$PORT_A"
wait_health "http://127.0.0.1:$PORT_B"

phase "same-LAN topology"
docker network inspect sage-v11176-federation-lan >/dev/null 2>&1 || \
  docker network create --internal sage-v11176-federation-lan >/dev/null
docker network connect --alias node-a sage-v11176-federation-lan "$(container_id node-a)"
docker network connect --alias node-b sage-v11176-federation-lan "$(container_id node-b)"
dc exec -T node-a getent hosts node-b >/dev/null
dc exec -T node-b getent hosts node-a >/dev/null

existing_a=$(api node-a GET /v1/dashboard/federation/connections)
existing_b=$(api node-b GET /v1/dashboard/federation/connections)
existing_count_a=$(jfield "$existing_a" connections.length)
existing_count_b=$(jfield "$existing_b" connections.length)
if [ "$existing_count_a" -gt 0 ] && [ "$existing_count_b" -gt 0 ]; then
  phase "reuse persisted active JOIN agreement"
  chain_a=$(jfield "$existing_a" connections.0.remote_chain_id)
  chain_b=$(jfield "$existing_b" connections.0.remote_chain_id)
elif [ -n "${FED_ACCEPTANCE_PAIR_COMMAND:-}" ]; then
  phase "pair nodes and enable reciprocal Mynah read/message contacts"
  sh -c "$FED_ACCEPTANCE_PAIR_COMMAND"
else
  phase "automatic real JOIN ceremony over LAN"
  endpoint_a="https://$(lan_ip node-a):8444"
  endpoint_b="https://$(lan_ip node-b):8444"
  create_body=$(node -e 'process.stdout.write(JSON.stringify({endpoint:process.argv[1],transport:""}))' "$endpoint_a")
  created=$(api node-a POST /v1/dashboard/federation/join/host/create \
    "$create_body")
  sid=$(jfield "$created" session_id)
  uri=$(jfield "$created" otpauth_uri)
  scan_body=$(node -e 'process.stdout.write(JSON.stringify({uri:process.argv[1],endpoint:process.argv[2]}))' "$uri" "$endpoint_b")
  scanned=$(api node-b POST /v1/dashboard/federation/join/guest/scan "$scan_body")
  return_uri=$(jfield "$scanned" return_uri)
  scan_return=$(node -e 'process.stdout.write(JSON.stringify({session_id:process.argv[1],return_uri:process.argv[2]}))' "$sid" "$return_uri")
  api node-a POST /v1/dashboard/federation/join/host/scan-return "$scan_return" >/dev/null
  request_body=$(node -e 'process.stdout.write(JSON.stringify({session_id:process.argv[1],endpoint:process.argv[2],max_clearance:4,allowed_domains:[],mode:"exchange",direction:"both"}))' "$sid" "$endpoint_b")
  requested=$(api node-b POST /v1/dashboard/federation/join/guest/request "$request_body")
  code_g=$(jfield "$requested" code_g)
  approve_body=$(node -e 'process.stdout.write(JSON.stringify({typed_code:process.argv[1],max_clearance:4,allowed_domains:[],mode:"exchange",direction:"both"}))' "$code_g")
  api node-a POST "/v1/dashboard/federation/join/host/$sid/approve" "$approve_body" >/dev/null
  guest_status=$(api node-b GET "/v1/dashboard/federation/join/guest/$sid/status")
  host_scope=$(jfield "$guest_status" host_scope)
  confirm_body=$(node -e 'process.stdout.write(JSON.stringify({session_id:process.argv[1],endpoint:process.argv[2],host_scope:JSON.parse(process.argv[3])}))' "$sid" "$endpoint_b" "$host_scope")
  api node-b POST /v1/dashboard/federation/join/guest/confirm "$confirm_body" >/dev/null
  chain_a=$(jfield "$(api node-a GET /v1/dashboard/federation/connections)" connections.0.remote_chain_id)
  chain_b=$(jfield "$(api node-b GET /v1/dashboard/federation/connections)" connections.0.remote_chain_id)
  [ -n "$chain_a" ] && [ -n "$chain_b" ] || die "JOIN returned no active connection"
fi

if [ "$MODE" = full ]; then
  phase "wait for governed app-v26 companion and receipt activation (bounded 45m)"
  deadline=$(( $(date +%s) + 2700 ))
  while :; do
    status_a=$(mcp_call node-a sage_status '{}') || true
    status_b=$(mcp_call node-b sage_status '{}') || true
    state_a=$(jfield "$status_a" enrollment_status 2>/dev/null || true)
    state_b=$(jfield "$status_b" enrollment_status 2>/dev/null || true)
    ready_a=$(api node-a GET /v1/dashboard/federation/readiness)
    ready_b=$(api node-b GET /v1/dashboard/federation/readiness)
    app_a=$(jfield "$ready_a" app_version)
    app_b=$(jfield "$ready_b" app_version)
    if [ "$state_a" = active ] && [ "$state_b" = active ] &&
       [ "$app_a" -ge 26 ] && [ "$app_b" -ge 26 ]; then
      break
    fi
    [ "$(date +%s)" -lt "$deadline" ] || die "Mynah companions and receipt-v2 did not activate within 45m"
    echo "waiting: A app=$app_a height=$(jfield "$ready_a" block_height); B app=$app_b height=$(jfield "$ready_b" block_height); Mynah=$state_a/$state_b"
    sleep 20
  done
  agent_a=$(jfield "$status_a" agent_id)
  agent_b=$(jfield "$status_b" agent_id)

  phase "grant reciprocal Mynah home-domain read and exact inbox consent"
  perms_a='{"permissions":[{"domain":"mynah-a-home","read":true,"write":false,"copy":false}]}'
  perms_b='{"permissions":[{"domain":"mynah-b-home","read":true,"write":false,"copy":false}]}'
  api node-a PUT "/v1/dashboard/federation/connections/$chain_a/permissions" "$perms_a" >/dev/null
  api node-b PUT "/v1/dashboard/federation/connections/$chain_b/permissions" "$perms_b" >/dev/null
  local_a=$(api node-a GET "/v1/dashboard/federation/connections/$chain_a/pipe-contacts?agent_id=$agent_a&live=1")
  local_b=$(api node-b GET "/v1/dashboard/federation/connections/$chain_b/pipe-contacts?agent_id=$agent_b&live=1")
  contact_a=$(jfield "$local_a" local_contacts.contacts.0.contact_id)
  contact_b=$(jfield "$local_b" local_contacts.contacts.0.contact_id)
  accept_a=$(node -e 'process.stdout.write(JSON.stringify({agent_id:process.argv[1],contact_id:process.argv[2],accepting:true}))' "$agent_a" "$contact_a")
  accept_b=$(node -e 'process.stdout.write(JSON.stringify({agent_id:process.argv[1],contact_id:process.argv[2],accepting:true}))' "$agent_b" "$contact_b")
  api node-a PUT "/v1/dashboard/federation/connections/$chain_a/pipe-contacts" "$accept_a" >/dev/null
  api node-b PUT "/v1/dashboard/federation/connections/$chain_b/pipe-contacts" "$accept_b" >/dev/null
fi

phase "remove LAN; only the relay bridges edge_a and edge_b"
docker network disconnect sage-v11176-federation-lan "$(container_id node-a)"
docker network disconnect sage-v11176-federation-lan "$(container_id node-b)"

phase "restart A, B, then both and require container IP churn"
for svc in node-a node-b; do
  before=$(container_ip "$svc")
  dc stop "$svc" >/dev/null
  dc rm -f "$svc" >/dev/null
  case "$svc" in
    node-a) edge=sage-v11176-federation-edge-a; control=sage-v11176-federation-control-a ;;
    node-b) edge=sage-v11176-federation-edge-b; control=sage-v11176-federation-control-b ;;
  esac
  # Occupy the just-freed addresses so Docker cannot hand the recreated node
  # the same pair and accidentally skip the stale-address recovery condition.
  churn_id=$(docker run -d --rm --network "$edge" alpine:3.22 sleep 300)
  CHURN_IDS="$CHURN_IDS $churn_id"
  docker network connect "$control" "$churn_id"
  dc up -d "$svc" >/dev/null
  [ "$svc" = node-a ] && wait_health "http://127.0.0.1:$PORT_A" || wait_health "http://127.0.0.1:$PORT_B"
  after=$(container_ip "$svc")
  docker stop "$churn_id" >/dev/null
  [ "$before" != "$after" ] || die "Docker reused $svc IP ($after); address-churn gate did not run"
done
dc restart node-a node-b >/dev/null
wait_health "http://127.0.0.1:$PORT_A"
wait_health "http://127.0.0.1:$PORT_B"

phase "relay outage and recovery"
dc stop relay >/dev/null
sleep 2
dc start relay >/dev/null
wait_health "http://127.0.0.1:$PORT_A"
wait_health "http://127.0.0.1:$PORT_B"

phase "expired route snapshot fixture"
now=$(date +%s)
past=$((now - 60))
for dir in "$STATE/a" "$STATE/b"; do
  if grep -q 'expires_at:' "$dir/config.yaml"; then
    sed -E -i.bak "s/^([[:space:]]*)expires_at:.*/\\1expires_at: $past/" "$dir/config.yaml"
    rm -f "$dir/config.yaml.bak"
  else
    echo "WARN: no authenticated p2p_routes snapshot exists; pair/flow driver must create it" >&2
  fi
done
dc restart node-a node-b >/dev/null
wait_health "http://127.0.0.1:$PORT_A"
wait_health "http://127.0.0.1:$PORT_B"

phase "v11.17.4 persisted p2p_peers compatibility shape"
grep -q 'p2p_peers:' "$ROOT/deploy/federation-acceptance/v11.17.4-config.template.yaml"
if [ -n "${FED_ACCEPTANCE_MIGRATION_COMMAND:-}" ]; then
  sh -c "$FED_ACCEPTANCE_MIGRATION_COMMAND"
elif [ "$MODE" = full ]; then
  dc stop node-a >/dev/null
  grep -q 'p2p_peers:' "$STATE/a/config.yaml" || die "paired node has no compatibility p2p_peers"
  sed -i.bak '/^[[:space:]]*p2p_routes:/,/^[[:space:]]*p2p_force_private:/{ /p2p_force_private:/!d; }' "$STATE/a/config.yaml"
  rm -f "$STATE/a/config.yaml.bak"
  ! grep -q 'p2p_routes:' "$STATE/a/config.yaml" || die "legacy fixture still contains p2p_routes"
  dc start node-a >/dev/null
  wait_health "http://127.0.0.1:$PORT_A"
  i=0
  until grep -q 'p2p_routes:' "$STATE/a/config.yaml"; do
    api node-a GET "/v1/dashboard/federation/connections/$chain_a/status" >/dev/null || true
    i=$((i + 1)); [ "$i" -lt 30 ] || die "v11.17.4 p2p_peers did not migrate to a current route snapshot"
    sleep 2
  done
fi

if [ -n "${FED_ACCEPTANCE_FLOW_COMMAND:-}" ]; then
  phase "canonical MCP flow: find -> send -> offline inbox -> read -> reply/status"
  sh -c "$FED_ACCEPTANCE_FLOW_COMMAND"
elif [ "$MODE" = full ]; then
  phase "canonical MCP flow: find -> send -> offline inbox -> read -> reply/status"
  find_args=$(node -e 'process.stdout.write(JSON.stringify({name:"mynah",peer_chain:process.argv[1]}))' "$chain_a")
  found=$(mcp_call node-a sage_find_agent "$find_args")
  target=$(jfield "$found" matches.0.to)
  [ -n "$target" ] || die "sage_find_agent returned no exact remote Mynah target"
  dc stop node-b >/dev/null
  send_args=$(node -e 'process.stdout.write(JSON.stringify({to:process.argv[1],intent:"acceptance",payload:"v11.17.6 durable offline inbox probe "+process.argv[2],idempotency_key:"v11176-offline-probe-"+process.argv[2]}))' "$target" "$RUN_TOKEN")
  send_started=$(date +%s)
  sent=$(mcp_call node-a sage_message_send "$send_args")
  send_elapsed=$(( $(date +%s) - send_started ))
  message_id=$(jfield "$sent" message_id)
  [ -n "$message_id" ] || die "sage_message_send returned no message_id"
  [ "$(jfield "$sent" idempotent_replay)" = false ] || die "offline probe replayed a prior run instead of admitting fresh work"
  [ "$(jfield "$sent" transport_status)" = queued ] || die "offline sage_message_send was not queued"
  [ "$(jfield "$sent" peer_status)" = unconfirmed ] || die "offline sage_message_send incorrectly claimed peer confirmation"
  [ "$send_elapsed" -le 5 ] || die "offline sage_message_send was not immediate (${send_elapsed}s)"
  dc start node-b >/dev/null
  wait_health "http://127.0.0.1:$PORT_B"
  i=0
  while :; do
    inbox=$(mcp_call node-b sage_inbox '{"limit":5}') || true
    received_id=$(jfield "$inbox" items.0.message_id 2>/dev/null || true)
    [ -n "$received_id" ] && break
    i=$((i + 1)); [ "$i" -lt 45 ] || die "offline message did not persist/deliver to restarted inbox"
    sleep 2
  done
  reply_args=$(node -e 'process.stdout.write(JSON.stringify({message_id:process.argv[1],result:"v11.17.6 acceptance reply"}))' "$received_id")
  mcp_call node-b sage_message_reply "$reply_args" >/dev/null
  status_args=$(node -e 'process.stdout.write(JSON.stringify({message_id:process.argv[1]}))' "$message_id")
  i=0
  while :; do
    final_status=$(mcp_call node-a sage_message_status "$status_args") || true
    read_status=$(jfield "$final_status" read_status 2>/dev/null || true)
    workflow_status=$(jfield "$final_status" workflow_status 2>/dev/null || true)
    [ "$read_status" = confirmed ] && [ "$workflow_status" = completed ] && break
    i=$((i + 1)); [ "$i" -lt 45 ] || die "sender status lacks confirmed read and completed reply after retry window (read=$read_status workflow=$workflow_status)"
    sleep 2
  done
fi

phase "PASS ($MODE)"
