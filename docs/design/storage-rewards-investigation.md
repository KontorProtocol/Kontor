# Storage rewards: investigation and implementation proposal

Status: implemented on `feat/storage-reward-accounting`, 2026-09-09, including
accrual, allocated-only issuance, claims, immediate exhaustion cutoff, and bounded
cleanup. Baseline: main `e5eef308351ae0335aa3da25e6fdd7667301efe3` (#552).
The [accounting design](storage-reward-accounting.md) describes the implementation
and its validation; this document retains the policy decisions and research.
Formula reference: PR #441, `f9763da256ab36f299a9adf45051b985ac42ffc1` (head verified with GitHub
during this investigation).

## Accepted direction (2026-09-08)

The user agreed to both recommendations after the cross-network comparison:

1. Storage hosts earn through lazy accounting and may claim while remaining in
   their agreements. Joining or leaving is an accounting boundary, not a payment
   prerequisite. Validator ordering rewards retain their existing automatic
   per-block credits to bonded balances.
2. Mint only storage rewards allocated to actual recipients. The part attributable
   to genesis dilution or other structurally unallocated shares remains unminted.
   This explicitly changes realized inflation relative to minting the entire
   nominal storage share. Preserve the adoption ramp; the initial weight 1000
   remains a preproduction calibration rather than a newly validated constant.

Claims must not create additional emission. Rounding reserves must be bounded and
accounted for separately from structurally unallocated amounts. Agreement and
membership lifecycle changes must not retrospectively alter earned rewards.

After the follow-up research, the user accepted the immediate on-chain cutoff:
when a penalty reduces a storer's bond to zero, stop future storage rewards and
preserve rewards earned before that event. Bounded membership cleanup may finish
later, but its backlog must not extend reward eligibility. This does not add debt
or forfeiture of earlier unclaimed income. Re-entry remains gated by cleanup.

## Findings

The existing decisions in [the economic overview](../economic-layer-overview.md)
and [the reactor integration design](../reactor-economic-integration.md) already
choose storage yield allocated by frozen agreement weight, equally among its hosts,
with lazy claims. They accept the content-blind yield/self-dealing consequence.
This does not mean multiplying each host's entire current bond by a reward rate.
Extra uncommitted collateral is not an extra agreement membership.

Current main has:

- Frozen `AgreementData.storage_weight` and `required_collateral`.
- `ProtocolState.total_storage_weight` starting at 1000 and growing once per
  agreement activation. Activation is one-way; leaving the last host does not
  remove the agreement's weight or deactivate it.
- Signer-keyed memberships, independent of validator registration. Positive
  collateral shortfalls preserve memberships and obligations.
- Bounded penalty settlement and zero-bond cleanup. The cleanup flag stops new
  admission and challenge assignment immediately; individual membership rows can
  remain active until a later cleanup step.
- `HolderRef::StoragePool`, but no storage mint, payout, or claim API.
- `token::mint_emission` computes the scheduled total from current supply, mints
  its 10% ordering share when ordering recipients exist, and reports the other
  90% as `storage_unminted`.

PR #441 is a formula/test reference, not a patch to merge intact. Its
`distribute_storage_rewards` scans agreements and their hosts, constructs a payout
vector and returns allocations. It does not fund and execute an atomic claim path.
Its old membership representation, redistribution-related affordances and leave
restrictions must not be imported into current main incidentally.

## Genesis dilution: purpose versus evidence

The mathematical effect of Ω_genesis is to keep the first few files from receiving
the entire scheduled storage budget. With real weight W, their combined fraction
is W / (1000 + W), increasing toward one as real storage weight grows. This is a
reward ramp with storage adoption; it also suppresses bootstrap hosts' income.
It is not necessary for the lazy accumulator, and it does not by itself distinguish
valuable files from self-created files.

That motivation is an inference from the formula, not a confirmed explanation of
why 1000 was selected. PR #441 and the integration design include the dilution,
but the local Documentation repository's `docs/economics/perpetual.mdx` instead
describes Ω as the sum of actual file weights without the genesis term. Its prose
also emphasizes bootstrap rewards. The available documents therefore do not give
one consistent, fully justified account of this parameter. Confirm the modeling
rationale before treating the initial 1000 or its unallocated share as mandatory.

## Implemented accounting and the earlier proposal

The initial proposal used a global accumulator and a second accumulator per file.
That made ordinary membership changes inexpensive, but did not by itself solve
immediate cutoff and allocated-only issuance: stopping one host could require
visiting every file it served, while removing its memberships could require
updating every other host in those files.

The implementation instead caches each host's combined earning weight and keeps
one global reward index. Exhaustion settles the host and removes its full eligible
weight immediately. Ordinary joins and leaves settle the affected file's members;
large forced removals use bounded prepare/apply/fold steps. All survivors switch
to their increased share at one logical removal boundary. Until removal, the
exhausted slot's share stays unminted. Claims and block accrual take constant work.
The tradeoff is O(file membership) caller-paid work for ordinary joins and leaves,
and a temporary join/leave lock on the file undergoing forced reweighting.

Exact arithmetic uses token atoms, additional weight precision, and retained
per-host fractions. A global fractional liability counter funds the ceiling of
cumulative entitlement, keeping overfunding below one atom. The new wide
`mul-add-div-rem-integer` primitive returns a full 256-bit quotient and remainder;
it does not impose the older whole-Integer conversion ceiling on raw token atoms.
The follow-up [language audit](contract-language-reward-audit.md) expands ordinary
Integer arithmetic to the same range and removes contract-local numeric helpers.
The host call is metered
at the existing nontrivial numeric tier; full calibration remains #462.

See [Storage reward accounting](storage-reward-accounting.md) for formulas,
escrow authorization, rollback behavior, cleanup transitions, and validation.
All accounting uses ordinary versioned contract state and generated indexes,
without new SQL tables or a separate history. Preproduction history is disposable.

## Tracking

- #440 closed as superseded by #545 and #552; equivocation remains in #442.
- #442 updated with completed settlement work and the storage-reward investigation.
- #453 annotated with its obsolete base. Decision 3 already accepts a tunable 5M
  validator admission floor; implementation and calibration remain deferred.
- #553 tracks the intermittent macOS consensus-readiness timeout separately.
- #441 remains open as a formula/design reference until replacement work lands.

Housekeeping consequences checked before implementation, 2026-09-08:

| Tracker | Consequence of the completed storage-reward replacement |
| --- | --- |
| #441 | Supersede its scanning reward-distribution implementation. Close the old PR after the replacement merges, leaving its unresolved fee and agreement-deactivation proposals tracked in #442. This does not claim those proposals were implemented. |
| #442 | Complete the storage accumulator/emission/claims item after funding, cutoff and lifecycle checks pass. The economic umbrella stays open for its other items. |
| #444 | Reward conservation and rollback tests contribute coverage, but do not complete the deterministic simulation work. |
| #462 / #445 | The new numeric host call needs fuel metering; it does not complete gas calibration or congestion pricing. |
| #463 | Parameters still need their administration path. No closure. |
| #453 | Validator admission-floor work remains separate and must be re-derived against main. |

This branch completes the replacement needed for the #441 and #442 actions above;
apply those changes after merge. No additional currently open tracker was found
fully satisfied by the already merged settlement work;
#440 and #461 were already closed in the preceding housekeeping pass.

## Comparisons with other networks (researched 2026-09-08)

These comparisons concern documented mechanisms, not a full audit of the networks'
current implementations. They do not justify Kontor's numerical calibration.

### Filecoin: utility-dependent issuance

Filecoin divides its storage-mining allocation into 30% time-based simple minting
and 70% baseline minting. Baseline issuance depends on cumulative storage growth;
when the network falls behind the baseline, some issuance is deferred. The stated
motivation is to avoid concentrating subsidies in a launch rush followed by exits.
The simple component also supports early providers and providers during downturns.
This is a close economic comparison to an adoption-dependent reward ramp, but is
not Kontor's static additive denominator. Storage capacity is also not the same
as paying customer demand.

Sources: [minting specification](https://spec.filecoin.io/systems/filecoin_token/minting_model/)
and [FIP-0081's design rationale](https://github.com/filecoin-project/FIPs/blob/master/FIPS/fip-0081.md#design-rationale).
FIP-0081 changes collateral calculations; it is cited for its explanation of the
existing minting baseline, not as a new minting rule.

### Sia: storage customers pay hosts

Sia hosts earn payments under renter-funded storage contracts, subject to meeting
storage obligations. Sia's proof-of-work block rewards compensate miners. These
are separate sources of income. Its host payments therefore do not require dividing
a fixed storage-emission budget among a small number of early files.

Sources: [storage providers](https://devs.sia.storage/docs/core-concepts/storage-providers)
and [Siacoin and mining](https://docs.sia.tech/get-started-with-sia/learn-about-siacoins).

### Arweave: an endowment with an explicit future expense

Arweave's documented model combines inflation rewards, transaction fees and a
storage endowment funded by uploaders. Endowment withdrawals account for the
estimated storage burden and the other reward sources. Retained funds have an
explicit purpose: paying future storage costs. This is different from minting an
unassigned share merely because an allocation denominator contains genesis weight.

Sources: [lightpaper, section 5](https://arweave.org/files/arweave-lightpaper.pdf)
(describes protocol v2.7.0) and [current development overview](https://docs.arweave.org/developers/development/motivation).

### Cosmos SDK: claims do not require leaving

Cosmos SDK distribution uses cumulative reward accounting for delegators. They
can withdraw rewards while remaining delegated; changing a delegation also causes
reward accounting to settle. It retains referenced reward periods for slash-aware
calculations and deletes them when no references remain. This is useful prior art
for lazy accounting and checkpoint retention, not evidence that Kontor's storage
hosts must validate or that Cosmos solves our exact bounded-cleanup problem.

Source: [distribution module](https://docs.cosmos.network/sdk/latest/modules/distribution/README).

### Implication for Kontor

An adoption-dependent emission ramp has a concrete precedent in Filecoin. That
supports investigating the objective behind genesis dilution; it does not validate
1000 as the right weight, nor promise that the resulting reward covers bootstrap
hosts' costs. Other storage networks use different funding structures.

Accepted after this comparison: retain the ramp, express it explicitly as the
storage amount eligible for issuance, and mint that amount into the reward pool. Do not create a permanently unassigned
balance without a defined recipient or future use. This changes realized inflation
relative to minting the full nominal storage share, including the supply used to
calculate later emissions, and this economic change was explicitly accepted.

With all activated agreements having eligible hosts, W is real total file weight,
G is genesis weight, S is nominal storage emission, and w_f is one file's weight:

```
existing nominal allocation = S * w_f / (G + W)
issuance ramp              = S * W / (G + W)
file's share of issuance   = issuance ramp * w_f / W
```

These give the same per-file amount for the same inputs in exact arithmetic.
They do not prove equivalence after future supply changes or fixed-point rounding.
Empty agreements, exhausted-but-not-yet-removed slots and W=0 need explicit handling;
current monotonic activation weight must not be silently replaced by live weight.

For the payment UX, the proposal concerns storers joining/leaving particular file
agreements. It does not change the already implemented automatic ordering-reward
credits to validators' bonded balances. A storer can remain in its agreements and
claim regularly; participation changes are accounting boundaries, not a requirement
for receiving payments. Claim automation is a possible client feature, not something
implemented by this investigation.

## Reward cutoff versus cleanup: follow-up research (2026-09-08)

The user requested primary-source comparisons before choosing the zero-bond cutoff.
After this research, the user accepted the immediate on-chain cutoff and retention
of earlier earnings. The comparisons below explain the basis and limits of that
recommendation; they do not change Kontor's no-debt policy.

### Filecoin: eligibility changes independently of deferred work

The released v18 miner actor removes the declared terminated sectors' power within
`terminate_sectors`, even when `process_early_terminations` reports more work and
schedules a later cron batch. The request itself is bounded by sector/partition
limits. This is a concrete example of an eligibility state change being separated
from later penalty processing; it is not an unlimited all-sectors cleanup loop.

Source: [v18 miner actor](https://github.com/filecoin-project/builtin-actors/blob/v18.0.0/actors/miner/src/lib.rs#L2377),
including the power update at line 2508 and bounded processing at line 4110.
The same sections were also read on master at
`d894a1a536b2080228769742b5889748cbe8a549`.

Lotus's `MinerEligibleToMine` checks minimum power at a lookback state, then checks
positive claimed power, zero fee debt and absence of an active consensus fault at
the base state. It does not wait for all termination-queue work to finish before
checking eligibility. This is not literally Kontor's zero-bond rule: Filecoin's
power, debt, lookback and election semantics are different.

Source: [Lotus eligibility checks](https://github.com/filecoin-project/lotus/blob/445a242a0663c2dbf330d7ab8578528e5fa4ca67/chain/stmgr/actors.go#L422).

Preserving every previously earned reward is NOT a Filecoin invariant. It locks
rewards, and penalties can consume unvested rewards and create fee debt. Copying
that would change Kontor's agreed no-debt policy and the proposed scope of its
bond-only slash.

Sources: [Filecoin crypto-economics](https://docs.filecoin.io/basics/what-is-filecoin/crypto-economics)
and [miner accounting](https://spec.filecoin.io/systems/filecoin_mining/storage_mining/#section-systems.filecoin_mining.storage_mining.miner-accounting).

### Cosmos SDK: state-based eligibility, retained reward accounting

Jailing excludes a validator from the bonded set; unjailing is needed to become
eligible for rewards again. This is tied to protocol state transitions rather
than final deletion of all validator/delegator records. Distribution retains
reward periods and slash events for later claims, allowing before/after-slash
accounting without settling every delegator in the slash operation.

Sources: [slashing module](https://docs.cosmos.network/sdk/v0.53/build/modules/slashing/README)
and [distribution module](https://docs.cosmos.network/sdk/latest/modules/distribution/README).
This is a validator/delegator accounting analogy, not a proposal to couple Kontor
storage hosts to validators. Different chains can configure their reward rules.

### Sia: contract resolution determines the payment

A Sia storage contract specifies the payment outcome for successful storage and
for failure. The renter's escrow and host's collateral are contract-scoped, so
failure can remove that contract's payment as well as collateral. This does not
provide the same pooled-bond exhaustion scenario as Kontor, and is not evidence
that already-earned Kontor emissions should be forfeited.

Source: [Sia file contracts](https://sia.tech/learn/file-contracts).

### Polkadot: not every cutoff is instantaneous

For voluntary chilling, Polkadot documents continued participation through the
current era and ineligibility for the next era. This demonstrates a different
valid choice: a defined protocol boundary rather than immediate removal. It does
not establish what a fully slashed Kontor storage host should receive; voluntary
exit and collateral exhaustion are different events.

Source: [pause validating](https://docs.polkadot.com/node-infrastructure/run-a-validator/operational-tasks/pause-validating/).

### Recommendation for Kontor

Use the on-chain exhaustion event to stop future storage reward eligibility,
retain valid earlier earnings, and allow bounded membership cleanup to finish
later. The network comparisons support separating eligibility from cleanup, but
are not a universal rule that every chain immediately stops all rewards after
any slash. Retaining earlier earnings follows Kontor's chosen penalty scope; it
must not be presented as a rule shared by all other networks.

A same-block ordering convention must be explicit: with storage accrual before
penalty settlement, rewards already accrued in that block are retained and no
subsequent accrual is allowed for the exhausted account. A larger cleanup backlog
must not extend entitlement. Fresh bonding and re-entry remain gated by cleanup.

This research established the policy precedent. Kontor also needs to handle
changing per-file divisors and hosts serving many files. The implementation
addresses those interactions with cached weights and bounded reweighting, as
described in the [accounting design](storage-reward-accounting.md).
