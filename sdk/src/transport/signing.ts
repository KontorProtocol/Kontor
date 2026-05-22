/**
 * Taproot PSBT signing for Kontor commit/reveal transactions — the
 * shared signing primitives used by both `HttpTransport.submit` and the
 * attach/detach runtime (`Attachment`).
 *
 *   - `signCommit`  — the commit is a plain taproot key-path spend.
 *   - `signReveal`  — a reveal is a taproot *script*-path spend: the
 *                     compose response carries each input's tap-leaf
 *                     script separately, and the witness must be
 *                     assembled by hand (the Kontor reveal leaf is
 *                     non-standard, so `@scure/btc-signer`'s
 *                     `finalize()` can't build it).
 *
 * These were private to `HttpTransport` while `submit` was the only
 * caller; the attach/detach flow signs a chained commit → reveal →
 * reveal package by hand, so they live here as free functions over an
 * `Account`.
 */

import { hex } from "@scure/base";
import { TaprootControlBlock, Transaction, utils as btcUtils } from "@scure/btc-signer";

import type { Account } from "../account/index.js";
import type { ParticipantScripts } from "../bindings.js";
import { SignerError } from "../errors.js";

/**
 * Sign the commit PSBT — a taproot key-path spend — and return the
 * finalized raw transaction hex.
 */
export async function signCommit(
  account: Account,
  psbtHex: string,
): Promise<string> {
  const signed = await account.signPsbt(hex.decode(psbtHex));
  const tx = Transaction.fromPSBT(signed);
  tx.finalize();
  return hex.encode(tx.extract());
}

/**
 * Sign a reveal PSBT — a taproot script-path spend. Each input's leaf
 * script + control block (from the compose response's `per_participant`,
 * parallel to the PSBT inputs) is injected before signing, and the
 * witness — `[schnorr sig, leaf script, control block]` — assembled by
 * hand afterwards.
 */
export async function signReveal(
  account: Account,
  psbtHex: string,
  participants: ParticipantScripts[],
): Promise<string> {
  // Prepare: inject each input's leaf script + control block.
  const prep = Transaction.fromPSBT(hex.decode(psbtHex));
  participants.forEach((p, i) => {
    const leaf = p.commit_tap_leaf_script;
    const scriptWithVersion = btcUtils.concatBytes(
      hex.decode(leaf.script),
      new Uint8Array([leaf.leafVersion]),
    );
    const controlBlock = TaprootControlBlock.decode(
      hex.decode(leaf.controlBlock),
    );
    prep.updateInput(i, { tapLeafScript: [[controlBlock, scriptWithVersion]] }, true);
  });

  const signed = await account.signPsbt(prep.toPSBT());

  // Finalize by hand: witness = [schnorr sig, leaf script, control block].
  const tx = Transaction.fromPSBT(signed);
  participants.forEach((p, i) => {
    const sig = tx.getInput(i).tapScriptSig?.[0]?.[1];
    if (sig == null) {
      throw new SignerError(
        `reveal input ${i} was not signed by the account`,
        { docsPath: "/sdk/transport" },
      );
    }
    const leaf = p.commit_tap_leaf_script;
    tx.updateInput(i, {
      finalScriptWitness: [
        sig,
        hex.decode(leaf.script),
        hex.decode(leaf.controlBlock),
      ],
    });
  });
  return hex.encode(tx.extract());
}

/** Bitcoin txid (display order) of an already-serialized raw tx hex. */
export function txidOf(rawTxHex: string): string {
  // Lenient parse: a Kontor reveal carries a non-standard taproot leaf
  // and an OP_RETURN — we only want the txid, not script validation.
  return Transaction.fromRaw(hex.decode(rawTxHex), {
    disableScriptCheck: true,
    allowUnknownOutputs: true,
    allowUnknownInputs: true,
  }).id;
}
