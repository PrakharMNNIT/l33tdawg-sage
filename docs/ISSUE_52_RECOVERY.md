# Recovering a personal chain stranded at the upgrade admin-gate (issue #52)

## Symptom

A **personal (single-validator) chain** keeps producing **idle empty blocks** and stops
climbing the app-version fork ladder. The node log shows auto-advance giving up:

```
auto-advance halted: this node's agent.key is not the on-chain chain-admin, and past
app-v9 it can no longer self-grant that role (issue #52). repair-chain is disabled;
restore a complete stopped-node backup or use governed recovery.
```

## Cause

On a personal chain the node auto-advances up the app-version fork ladder by signing
upgrade proposals with the operator key (`~/.sage/agent.key`). From **app-v8** onward,
opening a governance proposal requires the proposer to hold the on-chain **`admin`** role.
The operator key's self-grant "open door" closes at **app-v9**, and `materializeAppV11Admin`
elects the *validator* key, not the agent key. So a chain that crossed app-v9 **without its
operator agent key being admin** can never open another proposal — auto-advance deadlocks,
and CometBFT keeps minting empty blocks because the app hash never reaches a fixed point.

## Are you affected?

| Chain | Status |
|-------|--------|
| **New personal chains** (created on this release or later) | **Protected automatically.** Genesis seeds the operator key as `admin` (`app_state.sage.initial_admin`), so the ladder climb never strands. |
| **Existing personal chains** created before this release | **At risk / possibly already stranded** past app-v9. Use the backup/governance guidance below. |
| **Multi-validator / federated chains** | **Not affected by this path.** Admin/governance is established via coordinated governance, not a local seed. Recover through governance. |

> A plain same-fork upgrade does **not** auto-recover an already-stranded chain.
> Automatic resets are disabled.

## Recovery

`sage-gui repair-chain` is disabled in v11.16.1. Its former implementation deleted
canonical Badger state and CometBFT block history, then treated SQLite as though it could
rebuild the chain. It cannot: SQLite is only a serving projection and does not contain
complete memory envelopes, RBAC, governance, validator, authorship, or historical-block
state.

Restore a complete backup taken while the node was stopped. If no full backup exists,
leave the chain unchanged and seek a governed, history-preserving recovery. Do not delete
Badger, CometBFT, `agent.key`, `vault.key`, or `genesis.json`.

`agent.key` is also the node's stable federation transport/operator identity, and peers
pin its public identity during JOIN. Restore the original key from backup. If it is
unrecoverable, treat this as a new node identity and explicitly re-pair every federation
peer; CEREBRUM Root handover does not rotate this transport key.
