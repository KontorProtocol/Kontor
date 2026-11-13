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
import { schnorr } from "@noble/curves/secp256k1.js";
import {
  Script,
  SigHash,
  TaprootControlBlock,
  Transaction,
} from "@scure/btc-signer";
import { tapLeafHash } from "@scure/btc-signer/payment.js";

import type { SignInput, Signing } from "../signing.js";
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
  const inputsToSign = Array.from(
    { length: prep.inputsLength },
    (_, index) => ({
      index,
    }),
  );
  const signed = await signing.psbt(hex.decode(psbtHex), {
    inputs: inputsToSign,
  });
  // Wallets may strip PSBT metadata when finalizing. Import only their
  // signature into the already validated request and verify its digest there.
  const returned = Transaction.fromPSBT(signed);
  assertUnsignedTransactionSame(prep, returned);
  for (let index = 0; index < prep.inputsLength; index++) {
    const input = returned.getInput(index);
    const witness = input.finalScriptWitness;
    const signature = input.tapKeySig ?? witness?.[0];
    if (signature?.length !== 64 || (witness != null && witness.length !== 1)) {
      throw new SignerError(
        `commit input ${index} has no default key-path signature`,
      );
    }
    prep.updateInput(index, { finalScriptWitness: [signature] });
  }
  verifyFinalizedTaprootTransaction(prep);
  return hex.encode(prep.extract());
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
  const inputsToSign: SignInput[] = [];
  for (let i = 0; i < prep.inputsLength; i++) {
    if (!ownsInput(i)) continue;
    const input = prep.getInput(i);
    if (input.tapLeafScript != null) {
      if (input.tapLeafScript.length !== 1) {
        throw new SignerError(`reveal input ${i} has ambiguous tap leaves`);
      }
      if (input.sighashType === SigHash.ALL_ANYONECANPAY) {
        inputsToSign.push({ index: i, sighash: "all-anyonecanpay" });
      } else if (input.sighashType === SigHash.SINGLE_ANYONECANPAY) {
        inputsToSign.push({ index: i, sighash: "single-anyonecanpay" });
      } else {
        throw new SignerError(
          `reveal input ${i} has unsupported script sighash`,
        );
      }
    } else {
      if (input.sighashType != null && input.sighashType !== 0) {
        throw new SignerError(
          `reveal input ${i} has unsupported key-path sighash`,
        );
      }
      inputsToSign.push({ index: i });
    }
  }
  // Pass the original PSBT bytes straight through — we only read
  // tap_internal_key from `prep`, no edits, no need to re-serialize.
  const signed = await signing.psbt(psbtBytes, { inputs: inputsToSign });

  // Keep the request's prevouts and leaves, even if the wallet returns
  // different or stripped metadata. The signature is checked against this
  // original transaction before it can be relayed.
  const returned = Transaction.fromPSBT(signed);
  assertUnsignedTransactionSame(prep, returned);
  const tx = prep;
  for (let i = 0; i < tx.inputsLength; i++) {
    if (!ownsInput(i)) continue;
    const input = returned.getInput(i);
    const tapLeafScript = tx.getInput(i).tapLeafScript?.[0];
    if (tapLeafScript != null) {
      const [controlBlock, scriptWithVersion] = tapLeafScript;
      const script = scriptWithVersion.slice(0, -1);
      const key = scriptSignerKey(script);
      const signatureEntry = input.tapScriptSig?.[0];
      const prefinalized = input.finalScriptWitness;
      const sig = signatureEntry?.[1] ?? prefinalized?.[0];
      if (sig == null) {
        throw new SignerError(
          `reveal input ${i} (script-path) was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      if (
        (signatureEntry != null &&
          (input.tapScriptSig?.length !== 1 ||
            !bytesEqual(signatureEntry[0].pubKey, key) ||
            !bytesEqual(signatureEntry[0].leafHash, tapLeafHash(script)))) ||
        (signatureEntry == null &&
          (prefinalized?.length !== 3 ||
            !bytesEqual(prefinalized[1]!, script) ||
            !bytesEqual(
              prefinalized[2]!,
              TaprootControlBlock.encode(controlBlock),
            ))) ||
        sig.length !== 65 ||
        sig[64] !== prep.getInput(i).sighashType
      ) {
        throw new SignerError(
          `reveal input ${i} has a different signed sighash`,
        );
      }
      // scriptWithVersion is `script || [leafVersion]`; the witness
      // wants the script bytes alone and the encoded control block.
      tx.updateInput(i, {
        finalScriptWitness: [
          sig,
          script,
          TaprootControlBlock.encode(controlBlock),
        ],
      });
    } else {
      const prefinalized = input.finalScriptWitness;
      const sig = input.tapKeySig ?? prefinalized?.[0];
      if (sig == null) {
        throw new SignerError(
          `reveal input ${i} (key-path) was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      if (
        sig.length !== 64 ||
        (prefinalized != null && prefinalized.length !== 1)
      ) {
        throw new SignerError(`reveal input ${i} changed key-path sighash`);
      }
      tx.updateInput(i, { finalScriptWitness: [sig] });
    }
  }
  verifyFinalizedTaprootTransaction(tx, true);
  return tx;
}

function scriptSignerKey(script: Uint8Array): Uint8Array {
  const decoded = Script.decode(script);
  if (
    !(decoded[0] instanceof Uint8Array) ||
    decoded[0].length !== 32 ||
    decoded[1] !== "CHECKSIG"
  ) {
    throw new SignerError("reveal leaf has no expected CHECKSIG key");
  }
  return decoded[0];
}

export function verifyFinalizedTaprootTransaction(
  tx: Transaction,
  allowMissingForeign = false,
): void {
  const prevouts = Array.from({ length: tx.inputsLength }, (_, index) => {
    const prevout = tx.getInput(index).witnessUtxo;
    if (prevout?.script == null || prevout.amount == null) {
      throw new SignerError(`input ${index} has no verified previous output`);
    }
    return prevout;
  });
  const scripts = prevouts.map((prevout) => prevout.script);
  const amounts = prevouts.map((prevout) => prevout.amount);
  for (let index = 0; index < tx.inputsLength; index++) {
    const input = tx.getInput(index);
    const witness = input.finalScriptWitness;
    if (witness == null || witness.length === 0) {
      if (allowMissingForeign) continue;
      throw new SignerError(`input ${index} has no final witness`);
    }
    const signature = witness[0]!;
    let key: Uint8Array;
    let digest: Uint8Array;
    if (witness.length === 1) {
      if (
        signature.length !== 64 ||
        (input.sighashType != null && input.sighashType !== 0) ||
        input.tapLeafScript?.length
      ) {
        throw new SignerError(`input ${index} has invalid key-path witness`);
      }
      const script = input.witnessUtxo!.script;
      if (script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
        throw new SignerError(`input ${index} does not spend a P2TR output`);
      }
      key = script.slice(2);
      digest = tx.preimageWitnessV1(index, scripts, 0, amounts);
    } else if (witness.length === 3) {
      const script = witness[1]!;
      const control = witness[2]!;
      const leaf = input.tapLeafScript?.[0];
      if (
        leaf == null ||
        leaf[1].at(-1) !== 0xc0 ||
        !bytesEqual(leaf[1].slice(0, -1), script) ||
        !bytesEqual(TaprootControlBlock.encode(leaf[0]), control) ||
        signature.length !== 65 ||
        input.sighashType !== signature[64] ||
        (signature[64] !== SigHash.ALL_ANYONECANPAY &&
          signature[64] !== SigHash.SINGLE_ANYONECANPAY)
      ) {
        throw new SignerError(`input ${index} has invalid script-path witness`);
      }
      key = scriptSignerKey(script);
      digest = tx.preimageWitnessV1(
        index,
        scripts,
        signature[64]!,
        amounts,
        -1,
        script,
        0xc0,
      );
    } else {
      throw new SignerError(`input ${index} has unexpected witness stack`);
    }
    if (!schnorr.verify(signature.slice(0, 64), digest, key)) {
      throw new SignerError(
        `input ${index} signature does not authorize this transaction`,
      );
    }
  }
}

/** Byte-wise equality for two same-length Uint8Arrays. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function assertUnsignedTransactionSame(
  requested: Transaction,
  returned: Transaction,
): void {
  if (
    !bytesEqual(requested.unsignedTx, returned.unsignedTx) ||
    requested.inputsLength !== returned.inputsLength
  ) {
    throw new SignerError("wallet changed the unsigned transaction");
  }
}
