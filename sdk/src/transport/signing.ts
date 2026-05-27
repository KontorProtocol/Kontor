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
import type { TapLeafScript } from "../bindings.js";
import { SignerError } from "../errors.js";

/**
 * Sign the commit PSBT — a taproot key-path spend — and return the
 * finalized raw transaction hex.
 */
export async function signCommit(
  account: Account,
  psbtHex: string,
): Promise<string> {
  // Explicit inputs spec: sats-connect-style wallets won't sign
  // without one. Every commit input belongs to this account
  // (the indexer fills `funding_utxo_ids` only with the seller's
  // UTXOs), so sign each one with the default sighash.
  const prep = Transaction.fromPSBT(hex.decode(psbtHex));
  const inputsToSign = Array.from({ length: prep.inputsLength }, (_, index) => ({
    index,
  }));
  const signed = await account.signPsbt(hex.decode(psbtHex), {
    inputs: inputsToSign,
  });
  const tx = Transaction.fromPSBT(signed);
  tx.finalize();
  return hex.encode(tx.extract());
}

/**
 * Sign a reveal PSBT. Inputs `0..leaves.length-1` are participant
 * inputs (taproot script-path spends): each one gets its `leaf script
 * + control block` injected before signing and a `[schnorr sig, leaf
 * script, control block]` witness assembled afterwards. Any input
 * past `leaves.length-1` is an `extra_inputs` entry — a plain
 * key-path spend, finalized with the tap key-sig alone.
 */
export async function signReveal(
  account: Account,
  psbtHex: string,
  leaves: TapLeafScript[],
): Promise<string> {
  // Prepare: inject each participant input's leaf script + control
  // block. The indexer puts these on the wire as the parallel
  // `commit_tap_leaf_scripts`, not on the PSBT, so we have to slot
  // them in before signing. Trailing `extra_inputs` are key-path
  // P2TR spends; they need `tapInternalKey` populated for the signer
  // to know which key to use (the indexer leaves that empty too).
  const prep = Transaction.fromPSBT(hex.decode(psbtHex));
  leaves.forEach((leaf, i) => {
    const scriptWithVersion = btcUtils.concatBytes(
      hex.decode(leaf.script),
      new Uint8Array([leaf.leafVersion]),
    );
    const controlBlock = TaprootControlBlock.decode(
      hex.decode(leaf.controlBlock),
    );
    prep.updateInput(i, { tapLeafScript: [[controlBlock, scriptWithVersion]] }, true);
  });
  const accountXOnly = hex.decode(account.xOnlyPubKey);
  for (let i = leaves.length; i < prep.inputsLength; i++) {
    prep.updateInput(i, { tapInternalKey: accountXOnly }, true);
  }

  // Explicit inputs spec: required by sats-connect-style wallets (Xverse,
  // Leather, etc.), which won't sign without one. Every input here
  // belongs to this account — participants 0..leaves.length-1 are
  // script-path, the rest are key-path `extra_inputs` — all signed
  // with default sighash.
  const inputsToSign = Array.from({ length: prep.inputsLength }, (_, index) => ({
    index,
  }));
  const signed = await account.signPsbt(prep.toPSBT(), { inputs: inputsToSign });

  // Finalize by hand. Participant inputs (0..leaves.length-1) get the
  // script-path witness; trailing `extra_inputs` are key-path.
  const tx = Transaction.fromPSBT(signed);
  for (let i = 0; i < tx.inputsLength; i++) {
    if (i < leaves.length) {
      const leaf = leaves[i]!;
      const sig = tx.getInput(i).tapScriptSig?.[0]?.[1];
      if (sig == null) {
        throw new SignerError(
          `reveal participant input ${i} was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      tx.updateInput(i, {
        finalScriptWitness: [
          sig,
          hex.decode(leaf.script),
          hex.decode(leaf.controlBlock),
        ],
      });
    } else {
      const sig = tx.getInput(i).tapKeySig;
      if (sig == null) {
        throw new SignerError(
          `reveal extra input ${i} was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      tx.updateInput(i, { finalScriptWitness: [sig] });
    }
  }
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

/**
 * Read output `vout` of `rawTxHex` and return it as a `Utxo`. The
 * compose endpoint tells us exactly which output is change (commit
 * tx's vout 1 by construction, reveal tx's index per `output_info`),
 * so callers know the index up front — this just lifts the value +
 * scriptPubKey out of the parsed tx for the change-tracking cursor.
 */
export function utxoAt(
  rawTxHex: string,
  vout: number,
): { txid: string; vout: number; value: bigint; scriptPubKey: string } {
  const tx = Transaction.fromRaw(hex.decode(rawTxHex), {
    disableScriptCheck: true,
    allowUnknownOutputs: true,
    allowUnknownInputs: true,
  });
  const out = tx.getOutput(vout);
  if (out.script == null || out.amount == null) {
    throw new Error(`utxoAt: tx ${tx.id} vout ${vout} has no script/amount`);
  }
  return {
    txid: tx.id,
    vout,
    value: out.amount,
    scriptPubKey: hex.encode(out.script),
  };
}
