/**
 * BLS-aggregate signing surface: `AggregateFragment` (one contributor's
 * authorization for one Inst, ready to ship to an aggregator) and the
 * shape of the `AggregateInfo` the aggregator attaches to the combined
 * `Insts` bundle before broadcast.
 *
 * Flow:
 *
 *   1. Contributor builds an Inst from a Contract method.
 *   2. Contributor calls `inst.signForAggregate(blsKey)` — fetches
 *      their on-chain `next_nonce`, builds the per-op signing message
 *      (`"KONTOR-OP-V1" ++ postcard((SignerRef, nonce, sponsored, Inst))`),
 *      BLS-signs it under `KONTOR_BLS_DST`, and returns this fragment.
 *   3. Contributor sends `fragment.serialize()` to the aggregator
 *      out-of-band (HTTP / websocket / IPC — SDK is agnostic).
 *   4. Aggregator deserializes each fragment, calls `fragment.verify()`
 *      to BLS-verify the contributor's signature locally.
 *   5. Aggregator calls `session.combineAggregate(fragments)` — combines
 *      every per-op signature into one 48-byte BLS aggregate signature
 *      and returns an `Insts<unknown[]>` ready to broadcast.
 *   6. Aggregator pays the Bitcoin fee on broadcast; the contributor
 *      Insts can't be altered (each carries its own per-op signature).
 *
 * Bytes the contributor signs match `bls_crypto::aggregate_signing_message`
 * (via the same `indexer-types` crate compiled into kontor-sdk wasm),
 * so the resulting BLS aggregate verifies on chain in the indexer's
 * `bls/aggregate.rs` flow.
 */

import { hex } from "@scure/base";

import {
  aggregateSigningMessage,
  blsVerify,
} from "./component/kontor-sdk.js";
import { SignerError } from "./errors.js";
import { bigIntReplacer, type WireInst } from "./json-codec.js";

/**
 * Wire shape of a fragment — exactly what `serialize()` emits as
 * base64-encoded JSON. Treat the fields as opaque; the shape can
 * evolve under semver.
 */
export interface AggregateFragmentData {
  /** Wire JSON of the contributor's `Inst` — the aggregator rebuilds
   *  the bundle's `ops` from these payloads. */
  inst: WireInst;
  /** The contributor's x-only pubkey, lowercase hex. Doubles as
   *  `SignerRef::XOnlyPubkey(...)` in the signing message. */
  signerXOnlyPubKey: string;
  /** The contributor's BLS pubkey, 96-byte compressed G2, lowercase
   *  hex. Carried in-band so `verify()` is offline. */
  blsPubkey: string;
  /** The signer-level nonce, serialized as a decimal string (it's a
   *  `u64` on the wire). */
  nonce: string;
  /** Whether the publisher (some other signer in the bundle) pays for
   *  this op. Default `false`. */
  sponsored: boolean;
  /** BLS signature over the per-op message, 48-byte compressed G1,
   *  lowercase hex. */
  signature: string;
}

export class AggregateFragment {
  constructor(readonly data: AggregateFragmentData) {}

  /**
   * Serialize to a transport-friendly string (base64 of JSON). The
   * aggregator passes the string through `AggregateFragment.deserialize`.
   */
  serialize(): string {
    return globalThis.btoa(JSON.stringify(this.data));
  }

  /**
   * Reverse of `serialize`. Throws `SignerError` if the input isn't a
   * well-formed fragment. Always call `verify()` before bundling.
   */
  static deserialize(s: string): AggregateFragment {
    let parsed: unknown;
    try {
      parsed = JSON.parse(globalThis.atob(s));
    } catch (e) {
      throw new SignerError("AggregateFragment.deserialize: invalid input", {
        cause: e instanceof Error ? e : undefined,
      });
    }
    if (!isFragmentShape(parsed)) {
      throw new SignerError(
        "AggregateFragment.deserialize: input missing required fields",
        {
          details:
            "expected { inst, signerXOnlyPubKey, blsPubkey, nonce, sponsored, signature }",
        },
      );
    }
    return new AggregateFragment(parsed);
  }

  /**
   * Recompute the per-op signing message and BLS-verify the
   * fragment's signature against its embedded `blsPubkey`. Returns
   * `true` only when the bytes verify under `KONTOR_BLS_DST`. False
   * (or thrown on malformed bytes) means the fragment must not be
   * combined.
   *
   * This does NOT check that `blsPubkey` matches the chain registry's
   * row for `signerXOnlyPubKey` — the aggregator can do that
   * separately via `session.transport.signer(...)` if it wants to
   * fail fast before broadcasting.
   */
  verify(): boolean {
    const claimJson = JSON.stringify({
      XOnlyPubkey: this.data.signerXOnlyPubKey,
    });
    const instJson = JSON.stringify(this.data.inst, bigIntReplacer);
    const msg = aggregateSigningMessage(
      claimJson,
      BigInt(this.data.nonce),
      this.data.sponsored,
      instJson,
    );
    return blsVerify(
      hex.decode(this.data.blsPubkey),
      msg,
      hex.decode(this.data.signature),
    );
  }
}

function isFragmentShape(v: unknown): v is AggregateFragmentData {
  if (v == null || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    o.inst != null &&
    typeof o.inst === "object" &&
    typeof o.signerXOnlyPubKey === "string" &&
    typeof o.blsPubkey === "string" &&
    typeof o.nonce === "string" &&
    typeof o.sponsored === "boolean" &&
    typeof o.signature === "string"
  );
}
