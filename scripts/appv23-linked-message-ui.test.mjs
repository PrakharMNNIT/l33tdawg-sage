import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
    appV23BuildMessageCandidates,
    appV23MessagePairIsProven,
} from '../web/static/js/appv23-linked-messages.js';

const appSource = await readFile(
    new URL('../web/static/js/app.js', import.meta.url),
    'utf8',
);

const offerStart = appSource.indexOf(
    'const loadRemoteHostedMessageOffers = async () => {',
);
const offerEnd = appSource.indexOf(
    '\n    const loadExactMessageConsent = async () => {',
    offerStart,
);
assert.notEqual(offerStart, -1, 'explicit signed-offer loader must exist');
assert.notEqual(offerEnd, -1, 'signed-offer loader must have a bounded body');
const offerLoader = appSource.slice(offerStart, offerEnd);
const receiverEffectMarker = appSource.indexOf(
    '// Choosing a receiver is local UI state only.',
);
const receiverEffectStart = appSource.lastIndexOf(
    '    useEffect(() => {',
    receiverEffectMarker,
);
const receiverEffectEnd = appSource.indexOf(
    '\n    useEffect(() => {',
    receiverEffectMarker,
);
assert.notEqual(receiverEffectMarker, -1, 'receiver privacy boundary must be documented');
assert.notEqual(receiverEffectStart, -1, 'receiver effect must have a bounded start');
assert.notEqual(receiverEffectEnd, -1, 'receiver effect must have a bounded end');
const receiverEffect = appSource.slice(receiverEffectStart, receiverEffectEnd);

test('changing the local receiver performs no remote candidate request', () => {
    assert.match(
        appSource,
        /onChange=\$\{e => setMessageLocalID\(e\.target\.value\)\}/,
        'receiver selection must remain a local state change',
    );
    assert.doesNotMatch(receiverEffect, /fetchAppV23RemoteHostedMessageCandidates|fedPeerStatus|fetch\(/);

    const candidateCalls = [
        ...appSource.matchAll(/fetchAppV23RemoteHostedMessageCandidates\(/g),
    ];
    assert.equal(
        candidateCalls.length,
        1,
        'the UI must have exactly one peer-hosted candidate request site',
    );
    assert.ok(
        candidateCalls[0].index >= offerStart && candidateCalls[0].index < offerEnd,
        'the only request site must be inside the explicit click-bound loader',
    );
});

test('explicit signed-offer check queries exactly the selected host chain', () => {
    assert.match(
        offerLoader,
        /fetchAppV23RemoteHostedMessageCandidates\(\s*messageOfferChainID, messageLocalID,\s*\)/,
    );
    assert.match(
        offerLoader,
        /messageOfferHosts\.find\(connection =>\s*connection\.remote_chain_id === messageOfferChainID\)/,
        'the request must resolve one explicitly selected active host',
    );
    assert.match(
        appSource,
        /<select value=\$\{messageOfferChainID\}[\s\S]*onClick=\$\{loadRemoteHostedMessageOffers\}/,
        'the request must be reachable only from the selected-host button',
    );

    const genericMisses = [
        ...offerLoader.matchAll(/No current signed offers were returned\./g),
    ];
    assert.equal(
        genericMisses.length,
        2,
        'empty and peer-error outcomes must remain indistinguishable',
    );
});

test('a signed host offer for receiver X is unavailable for receiver Y', () => {
    const receiverX = 'a'.repeat(64);
    const receiverY = 'b'.repeat(64);
    const remoteAgentID = 'c'.repeat(64);
    const offer = {
        remote_chain_id: 'host-chain',
        remote_agent_id: remoteAgentID,
        local_agent_id: receiverX,
        group_ids: ['hosted-team'],
    };

    const forX = appV23BuildMessageCandidates({
        localAgentID: receiverX,
        peerHostedOffers: [offer],
    });
    const forY = appV23BuildMessageCandidates({
        localAgentID: receiverY,
        peerHostedOffers: [offer],
    });

    assert.equal(forX.length, 1);
    assert.equal(forX[0].local_agent_id, receiverX);
    assert.equal(appV23MessagePairIsProven(forX[0], receiverX), true);
    assert.deepEqual(forY, []);
    assert.equal(appV23MessagePairIsProven(forX[0], receiverY), false);
});

test('advertised-only or unlinked remote identities cannot enable consent review', () => {
    const localAgentID = 'a'.repeat(64);
    const remoteAgentID = 'c'.repeat(64);
    const selectedLinkedRemote = {
        remote_chain_id: 'remote-chain',
        remote_agent_id: remoteAgentID,
        label: 'Advertised agent',
    };
    const groups = [{
        group_id: 'local-team',
        members: [localAgentID],
    }];

    const advertisedOnly = appV23BuildMessageCandidates({
        selectedLinkedRemote,
        localAgentID,
        groups,
        linkedLinks: [],
    });
    const staleLink = appV23BuildMessageCandidates({
        selectedLinkedRemote,
        localAgentID,
        groups,
        linkedLinks: [{
            effective_state: 'active',
            binding_current: false,
            guest: {
                group_id: 'local-team',
                remote_chain_id: 'remote-chain',
                remote_agent_id: remoteAgentID,
                state: 'active',
            },
        }],
    });
    const activeLink = {
        effective_state: 'active',
        binding_current: true,
        guest: {
            group_id: 'local-team',
            remote_chain_id: 'remote-chain',
            remote_agent_id: remoteAgentID,
            state: 'active',
        },
    };
    const receiverOutsideGroup = appV23BuildMessageCandidates({
        selectedLinkedRemote,
        localAgentID,
        groups: [{ group_id: 'local-team', members: ['d'.repeat(64)] }],
        linkedLinks: [activeLink],
    });
    const exactCurrentPair = appV23BuildMessageCandidates({
        selectedLinkedRemote,
        localAgentID,
        groups,
        linkedLinks: [activeLink],
    });

    assert.deepEqual(advertisedOnly, []);
    assert.deepEqual(staleLink, []);
    assert.deepEqual(receiverOutsideGroup, []);
    assert.equal(exactCurrentPair.length, 1);
    assert.equal(exactCurrentPair[0].authorization_source, 'local_hosted_link');
    assert.equal(appV23MessagePairIsProven(exactCurrentPair[0], localAgentID), true);
    assert.match(
        appSource,
        /disabled=\$\{messageBusy \|\| !messagePairProven \|\| !messageLocal\}[\s\S]*onClick=\$\{loadExactMessageConsent\}/,
        'Review exact pair must stay disabled without a proven current pair',
    );
    assert.doesNotMatch(
        appSource,
        /<select value=\$\{selectedRemoteKey\}[\s\S]{0,500}Review exact pair/,
        'the messaging pane must not reuse the generic advertised/read-link selector',
    );
});
