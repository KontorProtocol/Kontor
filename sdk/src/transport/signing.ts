/**
 * Taproot PSBT signing for Kontor commit/reveal transactions — the
 * shared signing primitives used by both `HttpTransport.submit` and the
 * attach/detach runtime (`Attachment`).
 *
 *   - `signCommit`  — the commit is a plain taproot key-path spend.
 *   - `signReveal`  — a reveal may mix script-path participant inputs
 *                     with key-path `extra_inputs`. Each input's
 *                     signing recipe is read straight off the PSBT
 *                     (the indexer populates the standard BIP 371
 *                     fields), and inputs the calling account doesn't
 *                     own are skipped — caller finalizes those (e.g.
 *                     a buyer injects the seller's pre-signed SACP
 *                     witness in a marketplace swap).
 */

import { hex } from "@scure/base";
import { TaprootControlBlock, Transaction } from "@scure/btc-signer";

import type { Signing } from "../signing.js";
import { SignerError } from "../errors.js";

/**
 * Sign the commit PSBT — a taproot key-path spend — and return the
 * finalized raw transaction hex.
 */
export async function signCommit(
  signing: Signing,
  psbtHex: string,
): Promise<string> {
  // Explicit inputs spec: sats-connect-style wallets won't sign
  // without one. Every commit input belongs to this identity
  // (the indexer fills `funding_utxo_ids` only with the seller's
  // UTXOs), so sign each one with the default sighash.
  const prep = Transaction.fromPSBT(hex.decode(psbtHex));
  const inputsToSign = Array.from({ length: prep.inputsLength }, (_, index) => ({
    index,
  }));
  const signed = await signing.psbt(hex.decode(psbtHex), {
    inputs: inputsToSign,
  });
  const tx = Transaction.fromPSBT(signed);
  tx.finalize();
  return hex.encode(tx.extract());
}

/**
 * Sign a reveal PSBT. Walks the PSBT input array directly: an input
 * belongs to this account when its `tap_internal_key` matches the
 * account's x-only pubkey, and is script-path when it carries a
 * `tap_leaf_script`. Inputs whose `tap_internal_key` is missing or
 * doesn't match are treated as foreign — they aren't signed and
 * their witness isn't set here; the caller is responsible for those
 * (e.g. injecting a pre-signed SACP sig from a marketplace offer).
 *
 * Returns the parsed `Transaction` with owned inputs' witnesses set.
 * The caller calls `.extract()` once every input's witness is in
 * place. Returning the live object (instead of round-tripping
 * through PSBT hex) lets accept() inject the seller's pre-signed
 * witness without a re-parse, and lets the common all-owned case
 * extract directly.
 */
export async function signReveal(
  signing: Signing,
  psbtHex: string,
): Promise<Transaction> {
  const psbtBytes = hex.decode(psbtHex);
  const prep = Transaction.fromPSBT(psbtBytes);
  const ownXOnly = hex.decode(signing.identity.xOnlyPubKey);
  const ownsInput = (i: number): boolean => {
    const tik = prep.getInput(i).tapInternalKey;
    return tik != null && bytesEqual(tik, ownXOnly);
  };

  // Explicit inputs spec: sats-connect-style wallets won't sign
  // without one. Sign only the inputs this identity owns; the wallet
  // skips the rest.
  const inputsToSign: { index: number }[] = [];
  for (let i = 0; i < prep.inputsLength; i++) {
    if (ownsInput(i)) inputsToSign.push({ index: i });
  }
  // Pass the original PSBT bytes straight through — we only read
  // tap_internal_key from `prep`, no edits, no need to re-serialize.
  const signed = await signing.psbt(psbtBytes, { inputs: inputsToSign });

  // Finalize by hand. For each owned input, build the witness from
  // its leaf-script presence: script-path inputs land their schnorr
  // sig as `[sig, script, controlBlock]`; key-path inputs as
  // `[tapKeySig]`. Foreign inputs aren't touched.
  const tx = Transaction.fromPSBT(signed);
  for (let i = 0; i < tx.inputsLength; i++) {
    if (!ownsInput(i)) continue;
    const input = tx.getInput(i);
    const tapLeafScript = input.tapLeafScript?.[0];
    if (tapLeafScript != null) {
      const [controlBlock, scriptWithVersion] = tapLeafScript;
      const sig = input.tapScriptSig?.[0]?.[1];
      if (sig == null) {
        throw new SignerError(
          `reveal input ${i} (script-path) was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      // scriptWithVersion is `script || [leafVersion]`; the witness
      // wants the script bytes alone and the encoded control block.
      const script = scriptWithVersion.slice(0, -1);
      tx.updateInput(i, {
        finalScriptWitness: [sig, script, TaprootControlBlock.encode(controlBlock)],
      });
    } else {
      const sig = input.tapKeySig;
      if (sig == null) {
        throw new SignerError(
          `reveal input ${i} (key-path) was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      tx.updateInput(i, { finalScriptWitness: [sig] });
    }
  }
  return tx;
}

/** Byte-wise equality for two same-length Uint8Arrays. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
