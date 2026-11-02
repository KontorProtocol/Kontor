# Preparing and submitting upgrade approvals

The operator API prepares unsigned actions from closed canonical history. The
offline CLI inspects those bytes, signs an explicitly selected action, and
assembles approval files. Submission queues the resulting envelope at one node;
it does not establish consensus acceptance. This K5/K6 workflow does not yet
implement activation or the operator migration dry run, which remain unfinished.

Use the node API base URL, for example `http://localhost:8080/api`. Heights, voting
powers and nonces are decimal strings, including in SDK responses. Do not convert
them through JavaScript `Number` or floating-point JSON transformations.

## Prepare and inspect

Fetch `GET /protocol/upgrades` for the current protocol, pending plan, closed
reference and next-inclusion committee. Each committee entry supplies its public
`key`, registration `generation` and voting `power`. A generation identifies this
registration, not merely its public key. The state can change before inclusion.

Prepare a schedule with `POST /protocol/upgrades/prepare`:

```json
{
  "expires_at": "1100",
  "operation": {
    "kind": "schedule",
    "manifest_hex": "<canonical KPM1 manifest hexadecimal>",
    "activation_height": "2200"
  }
}
```

The example heights are illustrative. Choose an expiry and activation height
valid for the current canonical Bitcoin height. Schedule and Postpone require
1008 blocks of notice at inclusion; expiry is at most 144 Bitcoin blocks after
the referenced decision's Bitcoin position. The preparation endpoint validates
these conditions against its snapshot, but cannot guarantee later admission.

Postpone uses `{"kind":"postpone","activation_height":"2300"}`. Cancel uses
`{"kind":"cancel"}`. Both bind the current pending plan automatically; neither
can be prepared without one. Preparation does not grant consent or enqueue work.

Save the API response's `result` object as `preparation.json`, then inspect it:

```sh
jq -e '.result | {action_id, action_hex}' prepare-response.json > preparation.json
kontor upgrade-approval inspect --preparation preparation.json
```

Inspection decodes the canonical bytes, checks their action ID and displays every
signed field, including manifest definitions for Schedule. It ignores any extra
display metadata in the preparation file. Check the intended chain, current
protocol/era, action, target, activation, expiry and history reference. Independently
verify the proposed manifest and installed implementation. Once migration rehearsal
is available, run it before approval and repeat as activation approaches; a rehearsal
is advisory and never authorizes an upgrade.

Until the activation transition is implemented, a pending schedule prevents an
ordinary Bitcoin block at H or later from being proposed, accepted or applied.
Valid Cancel and Postpone actions remain eligible and have proposal priority.
This intermediate implementation must not be used to carry a network through an
activation. A replacement Bitcoin block is checked against the control state
that survives rollback to its parent, so removed schedules do not keep blocking
the chain and undoing a postponement or cancellation restores the prior boundary.

## Approve the exact action

Each approving validator uses its existing Ed25519 validator key as a local file
containing the hexadecimal 32-byte private key. Keep that file private. The command
accepts a file path, not key material in a command-line argument. It does not contact
a node or open consensus signing state.

```sh
kontor upgrade-approval sign \
  --preparation preparation.json \
  --key-file /secure/path/validator.key \
  --registration-generation '<current registration generation>' \
  --expected-action-id '<action ID you inspected and approved>' > approval.json
```

Do not blindly substitute the file's action ID into this command without checking
the action. The expected ID is the operator's explicit selection of the exact bytes.
Changing any signed field requires a new approval. The output contains only the
action ID, public key, registration generation and signature.

## Assemble and submit

Collect approvals for the same preparation, then assemble them:

```sh
kontor upgrade-approval assemble --preparation preparation.json \
  --approval-file validator-a.json --approval-file validator-b.json > assembled.json
jq -e '{envelope_hex}' assembled.json > submission.json
curl --fail-with-body -H 'Content-Type: application/json' \
  --data-binary @submission.json "$KONTOR_API_URL/protocol/upgrades"
```

Assembly verifies signatures and action bindings, sorts keys and rejects duplicate
keys. It does **not** establish current committee membership, quorum or admission.
The node checks those conditions again, including current registration generations,
voting power, canonical state, reference, expiry and rollback eligibility. Schedule
and Postpone need at least five-sixths of inclusion voting power; Cancel needs
strictly more than two-thirds. Submission accepts only `envelope_hex`, so extract
that field instead of sending the entire assembly report.

A `queued` result is a local, volatile acknowledgement. The proposer revalidates
the unchanged signed envelope before use. Competing queued work or temporarily
unfinished history can return HTTP 503; invalid actions return HTTP 400. Inspect
current state before deciding whether to retry. The SDK's separate `UpgradeClient`
provides `state`, `prepare` and `submit` with no automatic retry or signing.

## Rollback and fresh authorization

Rolling back Schedule removes its pending upgrade. Rolling back Postpone or Cancel
restores the earlier canonical control state. Authenticated decision history and
signing-safety records remain retained. Old approvals for a retracted action cannot
restore it, even if rollback restores the old nonce or pending plan.

If validators still intend the upgrade, read current state, prepare a fresh action,
inspect it, obtain fresh approvals and submit it again. There is no automatic
reapproval service. Ordinary historical reconstruction retains both the original
action and its later rollback; it does not treat the old approval as new consent.
