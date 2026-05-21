/**
 * Aggregate signing types: `AggregateFragment` (one contributor's
 * authorization for one Inst) and `AggregateInfo` (the assembled
 * authorization attached to an `Insts` bundle before broadcast).
 *
 * Flow:
 *
 *   1. Contributor builds an Inst from a Contract method.
 *   2. Contributor calls `inst.signForAggregate(signer)` → produces
 *      one `AggregateFragment` carrying the Inst payload + signer
 *      pubkey + Schnorr signature over the op-hash.
 *   3. Contributor sends `fragment.serialize()` to the aggregator
 *      out-of-band (HTTP, websocket, IPC — SDK is agnostic).
 *   4. Aggregator deserializes each fragment, calls `fragment.verify()`
 *      to validate the contributor's signature locally.
 *   5. Aggregator calls `session.combineAggregate(fragments)` to
 *      build the combined `Insts` bundle.
 *   6. Aggregator broadcasts (pays Bitcoin fees, cannot alter
 *      contributor Insts since each is individually signed).
 *
 * The wire format is base64-encoded JSON: opaque enough that
 * applications don't accidentally depend on internal shape, plain
 * enough to flow over any string transport.
 */

import { SignerError } from "./errors.js";

/**
 * Wire shape of a fragment. Public so applications can inspect what
 * they received, but treat fields as opaque (shape can evolve under
 * semver).
 */
export interface AggregateFragmentData {
  /** Stringified contract address (`<name>@<height>.<txIndex>`). */
  contract: string;
  /** Function name on the wire (kebab-case). */
  fnName: string;
  /** Encoded WAVE expression — `name(arg1, arg2, ...)`. */
  expr: string;
  /** Contributor's x-only public key, lowercase hex. */
  signerPubKey: string;
  /** Schnorr signature over the op-hash, lowercase hex. */
  signature: string;
}

/**
 * Aggregate authorization data attached to an `Insts` bundle. Built
 * by `session.combineAggregate(...)` from a set of contributor
 * fragments; mirrors the chain's `AggregateInfo` struct.
 */
export interface AggregateInfo {
  /** Per-contributor signing claims, in the same order as `Insts.insts`. */
  signers: ReadonlyArray<{
    signerPubKey: string;
    signature: string;
    nonce: bigint;
  }>;
  /** Optional publisher sponsorship marker for Sponsored-pay flows. */
  publisherSponsorship?: { publisherId: bigint };
}

export class AggregateFragment {
  constructor(readonly data: AggregateFragmentData) {}

  /**
   * Serialize to a transport-friendly string (base64-encoded JSON).
   * Aggregators receive these from contributors and pass them through
   * `AggregateFragment.deserialize(...)`.
   */
  serialize(): string {
    return globalThis.btoa(JSON.stringify(this.data));
  }

  /**
   * Reverse of `serialize`. Throws `SignerError` if the input isn't a
   * well-formed fragment string. Always call `verify()` before
   * trusting a fragment received from a peer.
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
            "expected { contract, fnName, expr, signerPubKey, signature }",
        },
      );
    }
    return new AggregateFragment(parsed);
  }

  /**
   * Verify the signature matches the Inst payload + signer pubkey.
   * Returns true on valid signature, false otherwise. Aggregators must
   * call this before bundling.
   */
  verify(): boolean {
    throw new SignerError("AggregateFragment.verify: not implemented", {
      docsPath: "/sdk/aggregate",
    });
  }
}

function isFragmentShape(v: unknown): v is AggregateFragmentData {
  if (v == null || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.contract === "string" &&
    typeof o.fnName === "string" &&
    typeof o.expr === "string" &&
    typeof o.signerPubKey === "string" &&
    typeof o.signature === "string"
  );
}
