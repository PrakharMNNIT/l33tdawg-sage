<!-- Verified against SAGE v11.18.0 lineage implementation (2026-08-07). -->

# Legacy upgrade-lineage repair (app-v21 → app-v22)

App-v22 requires canonical persisted `app-v6` through `app-v21` activation
records in strictly increasing committed heights. Some old production chains
activated those versions before every rung was persisted. The repair lane is a
narrow compatibility ceremony for that case; it is not a general state editor.

## Safety contract

- `sage-gui upgrade lineage status --json` and `doctor --json` are read-only.
- A repair is accepted only while the chain is exactly app-v21 and only inside
  an ordinary `app-v22` upgrade proposal.
- The manifest binds the chain ID-derived governance domain, the exact current
  valid-lineage digest, and the exact sorted missing-record set.
- Execution creates absent records only. It never overwrites a present record,
  including a malformed one. Exact replay is idempotent.
- Claimed activation heights must be positive, strictly ordered with every
  existing rung, and no later than the last committed application height.
- A manifest uses exactly one evidence mode. Mixing retained-Comet and legacy
  anchor claims is rejected.
- Lineage-repair proposals never auto-vote. Proposal creation records no
  implicit proposer vote, the validator background voter abstains, and this is
  also true on a one-validator chain. Every validator operator must explicitly
  review and vote.

## Retained-Comet workflow

First take and verify the normal operator backup of consensus and projection
state. Do not edit Badger keys, copy another validator's database, or use a
repair manifest as a substitute for a backup.

On the proposing validator, create the candidate manifest:

```text
sage-gui upgrade lineage doctor --json --manifest-out repair.json
```

Copy only that manifest to each validator operator. On every validator,
independently run:

```text
sage-gui upgrade lineage verify --json --manifest repair.json
```

`doctor` reads that node's retained `block_results` and block hash at the
claimed height. A block hash in a manifest is not consensus-verified proof by
itself; it is a claim about one validator's local archive. `verify` re-reads the
local chain ID, current lineage digest, exact missing set, consensus-parameter
app-version update, and block hash. Operators compare the emitted
`manifest_digest` across validators before proposing:

```text
sage-gui upgrade propose --target 22 --lineage-repair repair.json
```

After proposal creation, each validator inspects the immutable payload using
`sage_gov_status` (or CEREBRUM Governance) and explicitly calls
`sage_gov_vote` with `accept`, `reject`, or `abstain`. The REST equivalent is
the validator-local authenticated `POST /v1/governance/vote`. An operator must
not accept merely because another validator accepted.

After quorum, monitor `sage-gui upgrade status` until app-v22 activates, then
run `sage-gui upgrade lineage status --json` and confirm the immutable repair
audit and completed ladder on every validator before proceeding to app-v23.

## Pruned-history anchor fallback

If any required retained block result is unavailable, `doctor` will not blend
the surviving Comet claims with an anchor. The anchor file must state every
missing version and height:

```json
{"heights":{"9":123,"10":140}}
```

Generating an anchor manifest requires both `--legacy-anchor FILE` and the
deliberate `--acknowledge-unverified-anchor` flag. The manifest records
`operator-quorum-attested-unverified-history`; `verify` also requires the same
acknowledgement. These heights are audited operator assertions, not facts
recovered from retained history. An ACCEPT vote explicitly attests the exact
claims shown by `verify --json`.

## Persistence and recovery

Quorum execution stores the canonical manifest, its SHA-256 digest, proposal
ID, approval height, and exact created records in an immutable AppHash-covered
audit receipt. Boot and state-sync inspection verify that the duplicated audit
fields and record order/content still match the manifest and live applied
records. A mismatch fails closed.

Implementation: `internal/abci/appv22_lineage_repair.go`,
`internal/store/upgrade_lineage.go`, `cmd/sage-gui/upgrade_lineage.go`, and the
app-v22 upgrade proposal path in `internal/abci/app.go`.
