import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyFederationFailure,
  federationConnectionActionIntent,
  federationConnectionRoute,
  federationRoutePresentation,
  normalizeFederationRoutePlan,
} from '../web/static/js/federation-route-state.js';

test('prepared candidates never masquerade as an active route', () => {
  const plan = normalizeFederationRoutePlan({
    phase: 'prepared',
    state: 'ready',
    selected: { kind: 'direct' },
    candidates: [
      { kind: 'direct', ready: true },
      { kind: 'relay', ready: true },
    ],
    message: 'Using Direct now.',
  });
  const view = federationRoutePresentation(plan);

  assert.equal(plan.phase, 'prepared');
  assert.equal(plan.state, 'ready');
  assert.equal(plan.selected, null);
  assert.equal(view.label, 'Routes prepared');
  assert.doesNotMatch(view.detail, /\busing\b/i);
});

test('typed failures override a historical successful route', () => {
  const route = federationConnectionRoute({
    reachable: false,
    failure_state: 'trust_failure',
    error: 'agreement was revoked',
    route: {
      state: 'direct',
      active_kind: 'direct',
      last_success_at: '2026-07-23T00:00:00Z',
    },
  });
  const view = federationRoutePresentation(route);

  assert.equal(route.state, 'trust_failure');
  assert.equal(view.label, 'Trust check failed');
  assert.match(view.detail, /revoked/);
});

test('unreachable errors are classified before route history', () => {
  const security = federationConnectionRoute({
    reachable: false,
    error: 'SPKI pin mismatch',
    route: { state: 'direct', active_kind: 'direct' },
  });
  const offline = federationConnectionRoute({
    reachable: false,
    error: 'dial tcp: connection refused',
    route: { state: 'relay', active_kind: 'relay' },
  });

  assert.equal(security.state, 'security_blocked');
  assert.equal(federationRoutePresentation(security).label, 'Security blocked');
  assert.equal(offline.state, 'offline');
  assert.equal(federationRoutePresentation(offline).label, 'Offline');
});

test('a reachable peer without diagnostics is labelled compatible older SAGE', () => {
  const route = federationConnectionRoute({
    reachable: true,
    route: { state: 'unknown' },
  });

  assert.equal(route.state, 'old_peer');
  assert.equal(federationRoutePresentation(route).label, 'Older SAGE');
});

test('an authenticated active route may say which route is in use', () => {
  const route = federationConnectionRoute({
    reachable: true,
    route: { state: 'relay', active_kind: 'relay' },
  });
  const view = federationRoutePresentation(route);

  assert.equal(route.state, 'relay');
  assert.equal(view.label, 'Secure relay');
  assert.match(view.detail, /relayed/);
});

test('operator Retry diagnostics stay distinct and legacy routes require pairing again', () => {
  const expectations = [
    ['legacy_repair_required', 'Pair again required'],
    ['trust_generation_mismatch', 'Trust changed'],
    ['route_bundle_missing', 'Routes missing'],
    ['route_bundle_expired', 'Routes expired'],
    ['stale_direct', 'Direct route stale'],
    ['relay_unavailable', 'Secure relay unavailable'],
  ];
  for (const [failure_state, label] of expectations) {
    const route = federationConnectionRoute({ reachable: false, failure_state });
    assert.equal(route.state, failure_state);
    assert.equal(federationRoutePresentation(route).label, label);
  }
  assert.match(
    federationRoutePresentation({ state: 'legacy_repair_required' }).detail,
    /pair the two SAGEs again.*will not guess an identity/i,
  );
});

test('legacy repair routes to re-pair while ordinary failures route to retry', () => {
  assert.equal(federationConnectionActionIntent({ state: 'legacy_repair_required' }), 'pair_again');
  assert.equal(federationConnectionActionIntent({ state: 'offline' }), 'retry');
  assert.equal(federationConnectionActionIntent({ state: 'security_blocked' }), 'retry');
  assert.equal(federationConnectionActionIntent({ state: 'relay' }), 'toggle_pause');
});

// R3. One federated failure routinely carries BOTH security and
// route-availability text, because doPeerRequest races a p2p attempt and a
// direct attempt and joins both errors into a single message. Before R3 the
// availability regexes were tested first, so a pinned-trust mismatch that also
// lacked a p2p route was reported as the benign warn-tone 'route_bundle_missing'
// — telling an operator to look at their network when SAGE had actually refused
// the peer's identity.
test('security evidence outranks route-availability text in a combined failure', () => {
  const combined = 'peer chain-b unreachable: peer has no configured p2p route; '
    + 'x509: certificate signed by unknown authority';

  assert.equal(classifyFederationFailure({ error: combined }), 'security_blocked');
});

test('each security marker wins over each availability marker', () => {
  const securityMarkers = [
    'x509: certificate signed by unknown authority',
    'spki pin does not match',
    'pin mismatch for peer',
    'identity mismatch on peer certificate',
  ];
  const availabilityMarkers = [
    'peer has no configured p2p route',
    'no p2p dialer for peer',
    'route bundle is missing',
    'relay unavailable',
    'direct route is stale',
  ];

  for (const security of securityMarkers) {
    for (const availability of availabilityMarkers) {
      assert.equal(
        classifyFederationFailure({ error: `${availability}; ${security}` }),
        'security_blocked',
        `"${availability}" must not outrank "${security}"`,
      );
    }
  }
});

test('trust failures also outrank route-availability text', () => {
  assert.equal(
    classifyFederationFailure({ error: 'peer has no configured p2p route; agreement revoked' }),
    'trust_failure',
  );
});

test('availability text alone still classifies as availability', () => {
  assert.equal(
    classifyFederationFailure({ error: 'peer has no configured p2p route' }),
    'route_bundle_missing',
  );
  assert.equal(classifyFederationFailure({ error: 'relay unavailable' }), 'relay_unavailable');
});

test('a security failure presents as danger, not a routing warning', () => {
  const combined = 'peer has no configured p2p route; x509: certificate signed by unknown authority';
  const view = federationRoutePresentation({ state: classifyFederationFailure({ error: combined }) });

  assert.equal(view.tone, 'danger');
});
