/**
 * Caller-supplied "rider" outputs for a reveal tx — a payment (e.g. a
 * marketplace listing fee) or an OP_RETURN, settled atomically in the
 * same tx the SDK is already broadcasting.
 *
 * Deliberately a safe subset of the wire `RevealOutput`: the
 * SDK-managed variants (`Change`, the attach `ChainedEnvelope` escrow)
 * are not expressible here, so a caller can't accidentally displace the
 * change output or forge an escrow leaf.
 */

import { hex } from "@scure/base";
import { Address, OutScript } from "@scure/btc-signer";

import type { RevealOutput } from "./bindings.js";
import type { BitcoinNetwork } from "./chains.js";

export type ExtraOutput =
  | { pay: { address: string; value: bigint } }
  | { data: Uint8Array }; // OP_RETURN

/** Map one `ExtraOutput` to the wire `RevealOutput`. The `pay` address
 *  is decoded against `network`, so a malformed / wrong-network address
 *  throws here (surfaced to the caller as a compose-time error). */
export function toRevealOutput(
  extra: ExtraOutput,
  network: BitcoinNetwork,
): RevealOutput {
  if ("pay" in extra) {
    const decoded = Address(network).decode(extra.pay.address);
    if (decoded === undefined) {
      throw new Error(`invalid pay-to address: ${extra.pay.address}`);
    }
    return {
      Fixed: {
        script_pubkey: hex.encode(OutScript.encode(decoded)),
        value: Number(extra.pay.value),
      },
    };
  }
  return { OpReturn: { data: Array.from(extra.data) } };
}

export function toRevealOutputs(
  extras: ExtraOutput[] | undefined,
  network: BitcoinNetwork,
): RevealOutput[] {
  return (extras ?? []).map((e) => toRevealOutput(e, network));
}
